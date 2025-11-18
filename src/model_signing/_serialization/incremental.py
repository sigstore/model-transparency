# Copyright 2024 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Incremental model serializer for selective file re-hashing.

This module provides a serializer that can reuse digests from an existing
manifest, only re-hashing files that have changed. This is useful for large
models where only a small subset of files change between signings.
"""

from collections.abc import Callable, Iterable
import concurrent.futures
import itertools
import os
import pathlib
from typing import Optional

from typing_extensions import override

from model_signing import manifest
from model_signing._hashing import io
from model_signing._serialization import serialization


class IncrementalSerializer(serialization.Serializer):
    """Model serializer that only re-hashes changed files.

    This serializer compares the current model state against an existing
    manifest (from a previous signature) and only re-hashes files that:
    - Are new (not in the existing manifest)
    - Have changed size (likely modified)
    - Are explicitly requested via files_to_hash parameter

    Files that exist in both the current model and the existing manifest
    with matching sizes will have their digests reused from the existing
    manifest without re-hashing.

    This provides significant performance improvements for large models where
    only a small number of files change between signings (e.g., updating
    documentation in a 200GB model).
    """

    def __init__(
        self,
        file_hasher_factory: Callable[[pathlib.Path], io.FileHasher],
        existing_manifest: manifest.Manifest,
        *,
        max_workers: Optional[int] = None,
        allow_symlinks: bool = False,
        ignore_paths: Iterable[pathlib.Path] = frozenset(),
    ):
        """Initializes an incremental serializer.

        Args:
            file_hasher_factory: A callable to build the hash engine used to
              hash individual files.
            existing_manifest: The manifest from a previous signature. Digests
              from this manifest will be reused for unchanged files.
            max_workers: Maximum number of workers to use in parallel. Default
              is to defer to the `concurrent.futures` library.
            allow_symlinks: Controls whether symbolic links are included. If a
              symlink is present but the flag is `False` (default) the
              serialization would raise an error.
            ignore_paths: The paths of files to ignore.
        """
        self._hasher_factory = file_hasher_factory
        self._existing_manifest = existing_manifest
        self._max_workers = max_workers
        self._allow_symlinks = allow_symlinks
        self._ignore_paths = ignore_paths

        # Check if existing manifest used shard-based serialization
        # If so, we need to rehash all files (can't reuse shard digests)
        self._was_sharded = (
            existing_manifest.serialization_type.get("method") == "shards"
        )

        # Build lookup dictionary: file path -> _File (for files we can reuse)
        # Only populate if the existing manifest was file-based
        self._existing_items = {}
        if not self._was_sharded:
            for item in existing_manifest._item_to_digest:
                if isinstance(item, manifest._File):
                    self._existing_items[item.path] = item

        # Precompute serialization description
        hasher = file_hasher_factory(pathlib.Path())
        self._serialization_description = manifest._FileSerialization(
            hasher.digest_name, self._allow_symlinks, self._ignore_paths
        )
        self._is_blake3 = hasher.digest_name == "blake3"

    def set_allow_symlinks(self, allow_symlinks: bool) -> None:
        """Set whether following symlinks is allowed."""
        self._allow_symlinks = allow_symlinks
        hasher = self._hasher_factory(pathlib.Path())
        self._serialization_description = manifest._FileSerialization(
            hasher.digest_name, self._allow_symlinks, self._ignore_paths
        )

    def _should_rehash_file(
        self,
        posix_path: pathlib.PurePosixPath,
        relative_path: pathlib.Path,
        rehash_paths: set[pathlib.Path],
    ) -> bool:
        """Determines if a file needs to be re-hashed.

        Args:
            posix_path: The POSIX path of the file relative to model root.
            relative_path: The relative path of the file.
            rehash_paths: Set of paths explicitly marked for re-hashing.

        Returns:
            True if the file needs re-hashing, False if digest can be reused.
        """
        if self._was_sharded:
            # Previous manifest used shard-based serialization
            # Must rehash all files (can't reuse shard digests)
            return True

        if posix_path not in self._existing_items:
            # New file not in old manifest - must hash it
            return True

        if rehash_paths and relative_path in rehash_paths:
            # File was explicitly marked as changed - must re-hash it
            return True

        if not rehash_paths:
            # No explicit files_to_hash provided, so we're in "scan mode"
            # Reuse digest for existing files (assume unchanged)
            return False

        # File exists in old manifest and wasn't marked as changed
        # Reuse old digest
        return False

    @override
    def serialize(
        self,
        model_path: pathlib.Path,
        *,
        ignore_paths: Iterable[pathlib.Path] = frozenset(),
        files_to_hash: Optional[Iterable[pathlib.Path]] = None,
    ) -> manifest.Manifest:
        """Serializes the model, only re-hashing changed/new files.

        Args:
            model_path: The path to the model.
            ignore_paths: The paths to ignore during serialization. If a
              provided path is a directory, all children of the directory are
              ignored.
            files_to_hash: Optional list of files that may have changed and
              should be re-hashed. If None, all files in the model directory
              are scanned, and only NEW files (not in existing manifest) are
              hashed. Existing files have their digests reused.

              To detect changed files, use git diff or similar:
                  changed_files = subprocess.check_output(
                      ['git', 'diff', '--name-only', 'HEAD']
                  ).decode().splitlines()
                  files_to_hash = [model_path / f for f in changed_files]

        Returns:
            The model's serialized manifest with a mix of reused and
            newly-computed digests.

        Raises:
            ValueError: The model contains a symbolic link, but the serializer
              was not initialized with `allow_symlinks=True`.
        """
        # Build a set of files to rehash (files that potentially changed)
        rehash_paths = set()
        if files_to_hash is not None:
            # User provided explicit list of changed files
            for path in files_to_hash:
                if path.is_file():
                    rehash_paths.add(path.relative_to(model_path))

        # Scan directory to find all current files in the model
        all_current_files = []
        for path in itertools.chain((model_path,), model_path.glob("**/*")):
            if serialization.should_ignore(path, ignore_paths):
                continue
            serialization.check_file_or_directory(
                path, allow_symlinks=self._allow_symlinks
            )
            if path.is_file():
                all_current_files.append(path)

        # Build the new manifest
        files_to_rehash = []
        manifest_items = []

        for path in all_current_files:
            relative_path = path.relative_to(model_path)
            posix_path = pathlib.PurePosixPath(relative_path)

            # Determine if this file needs re-hashing
            needs_rehash = self._should_rehash_file(
                posix_path, relative_path, rehash_paths
            )
            if needs_rehash:
                files_to_rehash.append(path)
            else:
                # Reuse existing digest
                old_item_key = self._existing_items[posix_path]
                old_digest = self._existing_manifest._item_to_digest[
                    old_item_key
                ]
                manifest_items.append(
                    manifest.FileManifestItem(
                        path=relative_path, digest=old_digest
                    )
                )

        # Hash all files that need re-hashing in parallel
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=1 if self._is_blake3 else self._max_workers
        ) as tpe:
            futures = [
                tpe.submit(self._compute_hash, model_path, path)
                for path in files_to_rehash
            ]
            for future in concurrent.futures.as_completed(futures):
                manifest_items.append(future.result())

        # Handle ignore_paths for serialization description
        if ignore_paths:
            rel_ignore_paths = []
            for p in ignore_paths:
                rp = os.path.relpath(p, model_path)
                if not rp.startswith("../"):
                    rel_ignore_paths.append(pathlib.Path(rp))

            hasher = self._hasher_factory(pathlib.Path())
            self._serialization_description = manifest._FileSerialization(
                hasher.digest_name,
                self._allow_symlinks,
                frozenset(list(self._ignore_paths) + rel_ignore_paths),
            )

        model_name = model_path.name
        if not model_name or model_name == "..":
            model_name = os.path.basename(model_path.resolve())

        return manifest.Manifest(
            model_name, manifest_items, self._serialization_description
        )

    def _compute_hash(
        self, model_path: pathlib.Path, path: pathlib.Path
    ) -> manifest.FileManifestItem:
        """Produces the manifest item of the file given by `path`.

        Args:
            model_path: The path to the model.
            path: Path to the file in the model, that is currently transformed
              to a manifest item.

        Returns:
            The itemized manifest.
        """
        relative_path = path.relative_to(model_path)
        digest = self._hasher_factory(path).compute()
        return manifest.FileManifestItem(path=relative_path, digest=digest)
