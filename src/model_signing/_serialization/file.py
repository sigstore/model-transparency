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

"""Model serializers that operate at file level granularity."""

from collections.abc import Callable, Iterable
import concurrent.futures
import itertools
import os
import pathlib

from typing_extensions import override

from model_signing import manifest
from model_signing._hashing import io
from model_signing._serialization import serialization


class Serializer(serialization.Serializer):
    """Model serializer that produces a manifest recording every file.

    Traverses the model directory and creates digests for every file found,
    possibly in parallel.
    """

    def __init__(
        self,
        file_hasher_factory: Callable[[pathlib.Path], io.FileHasher],
        *,
        max_workers: int | None = None,
        allow_symlinks: bool = False,
        ignore_paths: Iterable[pathlib.Path] = frozenset(),
    ):
        """Initializes an instance to serialize a model with this serializer.

        Args:
            file_hasher_factory: A callable to build the hash engine used to
              hash individual files.
            max_workers: Maximum number of workers to use in parallel. Default
              is to defer to the `concurrent.futures` library.
            allow_symlinks: Controls whether symbolic links are included. If a
              symlink is present but the flag is `False` (default) the
              serialization would raise an error.
            ignore_paths: The paths of files to ignore.
        """
        self._hasher_factory = file_hasher_factory
        self._max_workers = max_workers
        self._allow_symlinks = allow_symlinks
        self._ignore_paths = ignore_paths

        # Precompute some private values only once by using a mock file hasher.
        # None of the arguments used to build the hasher are used.
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

    @override
    def serialize(
        self,
        model_path: pathlib.Path,
        *,
        ignore_paths: Iterable[pathlib.Path] = frozenset(),
        files_to_hash: Iterable[pathlib.Path] | None = None,
    ) -> manifest.Manifest:
        """Serializes the model given by the `model_path` argument.

        Args:
            model_path: The path to the model.
            ignore_paths: The paths to ignore during serialization. If a
              provided path is a directory, all children of the directory are
              ignored.
            files_to_hash: Optional list of files that are to be hashed;
              ignore all others

        Returns:
            The model's serialized manifest.

        Raises:
            ValueError: The model contains a symbolic link, but the serializer
              was not initialized with `allow_symlinks=True`.
        """
        paths = []
        # TODO: github.com/sigstore/model-transparency/issues/200 - When
        # Python3.12 is the minimum supported version, the glob can be replaced
        # with `pathlib.Path.walk` for a clearer interface, and some speed
        # improvement.
        if files_to_hash is None:
            files_to_hash = itertools.chain(
                (model_path,), model_path.glob("**/*")
            )
        for path in files_to_hash:
            if serialization.should_ignore(path, ignore_paths):
                continue
            serialization.check_file_or_directory(
                path, allow_symlinks=self._allow_symlinks
            )
            if path.is_file():
                paths.append(path)

        manifest_items = []
        with concurrent.futures.ThreadPoolExecutor(
            # blake3 parallelizes internally
            max_workers=1 if self._is_blake3 else self._max_workers
        ) as tpe:
            futures = [
                tpe.submit(self._compute_hash, model_path, path)
                for path in paths
            ]
            for future in concurrent.futures.as_completed(futures):
                manifest_items.append(future.result())

        # Recreate serialization_description for new ignore_paths
        if ignore_paths:
            rel_ignore_paths = []
            for p in ignore_paths:
                rp = os.path.relpath(p, model_path)
                # rp may start with "../" if it is not relative to model_path
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
