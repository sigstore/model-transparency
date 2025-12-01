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

"""Model serializers that operate at file shard level of granularity."""

from collections.abc import Callable, Iterable
import concurrent.futures
import itertools
import os
import pathlib

from typing_extensions import override

from model_signing import manifest
from model_signing._hashing import io
from model_signing._serialization import serialization


def _endpoints(step: int, end: int) -> Iterable[int]:
    """Yields numbers from `step` to `end` inclusive, spaced by `step`.

    Last value is always equal to `end`, even when `end` is not a multiple of
    `step`. There is always a value returned.

    Examples:
    ```python
    >>> list(_endpoints(2, 8))
    [2, 4, 6, 8]
    >>> list(_endpoints(2, 9))
    [2, 4, 6, 8, 9]
    >>> list(_endpoints(2, 2))
    [2]

    Yields:
        Values in the range, from `step` and up to `end`.
    """
    yield from range(step, end, step)
    yield end


class Serializer(serialization.Serializer):
    """Model serializer that produces a manifest recording every file shard.

    Traverses the model directory and creates digests for every file found,
    sharding the file in equal shards and computing the digests in parallel.
    """

    def __init__(
        self,
        sharded_hasher_factory: Callable[
            [pathlib.Path, int, int], io.ShardedFileHasher
        ],
        *,
        max_workers: int | None = None,
        allow_symlinks: bool = False,
        ignore_paths: Iterable[pathlib.Path] = frozenset(),
    ):
        """Initializes an instance to serialize a model with this serializer.

        Args:
            sharded_hasher_factory: A callable to build the hash engine used to
              hash every shard of the files in the model. Because each shard is
              processed in parallel, every thread needs to call the factory to
              start hashing. The arguments are the file, and the endpoints of
              the shard.
            max_workers: Maximum number of workers to use in parallel. Default
              is to defer to the `concurrent.futures` library.
            allow_symlinks: Controls whether symbolic links are included. If a
              symlink is present but the flag is `False` (default) the
              serialization would raise an error.
            ignore_paths: The paths of files to ignore.
        """
        self._hasher_factory = sharded_hasher_factory
        self._max_workers = max_workers
        self._allow_symlinks = allow_symlinks
        self._ignore_paths = ignore_paths

        # Precompute some private values only once by using a mock file hasher.
        # None of the arguments used to build the hasher are used.
        hasher = sharded_hasher_factory(pathlib.Path(), 0, 1)
        self._shard_size = hasher.shard_size
        self._serialization_description = manifest._ShardSerialization(
            # Here we need the internal hasher name, not the mangled name.
            # This name is used when guessing the hashing configuration.
            hasher._content_hasher.digest_name,
            self._shard_size,
            self._allow_symlinks,
            self._ignore_paths,
        )

    def set_allow_symlinks(self, allow_symlinks: bool) -> None:
        """Set whether following symlinks is allowed."""
        self._allow_symlinks = allow_symlinks
        hasher = self._hasher_factory(pathlib.Path(), 0, 1)
        self._serialization_description = manifest._ShardSerialization(
            hasher._content_hasher.digest_name,
            self._shard_size,
            self._allow_symlinks,
            self._ignore_paths,
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
            files_to_hash: Optional list of files to hash; ignore all others

        Returns:
            The model's serialized manifest.

        Raises:
            ValueError: The model contains a symbolic link, but the serializer
              was not initialized with `allow_symlinks=True`.
        """
        shards = []
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
                shards.extend(self._get_shards(path))

        manifest_items = []
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self._max_workers
        ) as tpe:
            futures = [
                tpe.submit(self._compute_hash, model_path, path, start, end)
                for path, start, end in shards
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

            hasher = self._hasher_factory(pathlib.Path(), 0, 1)
            self._serialization_description = manifest._ShardSerialization(
                hasher._content_hasher.digest_name,
                self._shard_size,
                self._allow_symlinks,
                frozenset(list(self._ignore_paths) + rel_ignore_paths),
            )

        model_name = model_path.name
        if not model_name or model_name == "..":
            model_name = os.path.basename(model_path.resolve())

        return manifest.Manifest(
            model_name, manifest_items, self._serialization_description
        )

    def _get_shards(
        self, path: pathlib.Path
    ) -> list[tuple[pathlib.Path, int, int]]:
        """Determines the shards of a given file path."""
        shards = []
        path_size = path.stat().st_size
        if path_size > 0:
            start = 0
            for end in _endpoints(self._shard_size, path_size):
                shards.append((path, start, end))
                start = end
        return shards

    def _compute_hash(
        self, model_path: pathlib.Path, path: pathlib.Path, start: int, end: int
    ) -> manifest.ShardedFileManifestItem:
        """Produces the manifest item of the file given by `path`.

        Args:
            model_path: The path to the model.
            path: Path to the file in the model, that is currently transformed
              to a manifest item.
            start: The start offset of the shard (included).
            end: The end offset of the shard (not included).

        Returns:
            The itemized manifest.
        """
        relative_path = path.relative_to(model_path)
        digest = self._hasher_factory(path, start, end).compute()
        return manifest.ShardedFileManifestItem(
            path=relative_path, digest=digest, start=start, end=end
        )
