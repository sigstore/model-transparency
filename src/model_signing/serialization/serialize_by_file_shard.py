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

"""Model serializers that operated at file shard level of granularity."""

import abc
import base64
from collections.abc import Callable, Iterable
import concurrent.futures
import itertools
import pathlib
from typing import Optional, cast

from typing_extensions import override

from model_signing.hashing import file
from model_signing.hashing import hashing
from model_signing.manifest import manifest
from model_signing.serialization import serialization
from model_signing.serialization import serialize_by_file


def _build_header(*, name: str, start: int, end: int) -> bytes:
    """Builds a header to encode a path with given name and shard range.

    Args:
        entry_name: The name of the entry to build the header for.
        start: Offset for the start of the path shard.
        end: Offset for the end of the path shard.

    Returns:
        A sequence of bytes that encodes all arguments as a sequence of UTF-8
        bytes. Each argument is separated by dots and the last byte is also a
        dot (so the file digest can be appended unambiguously).
    """
    # Prevent confusion if name has a "." inside by encoding to base64.
    encoded_name = base64.b64encode(name.encode("utf-8"))
    encoded_range = f"{start}-{end}".encode("utf-8")
    # Note: empty string at the end, to terminate header with a "."
    return b".".join([encoded_name, encoded_range, b""])


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


class ShardedFilesSerializer(serialization.Serializer):
    """Generic file shard serializer.

    Traverses the model directory and creates digests for every file found,
    sharding the file in equal shards and computing the digests in parallel.

    Subclasses can then create a manifest with these digests, either listing
    them item by item, combining them into file digests, or combining all of
    them into a single digest.
    """

    def __init__(
        self,
        sharded_hasher_factory: Callable[
            [pathlib.Path, int, int], file.ShardedFileHasher
        ],
        *,
        max_workers: Optional[int] = None,
        allow_symlinks: bool = False,
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
        """
        self._hasher_factory = sharded_hasher_factory
        self._max_workers = max_workers
        self._allow_symlinks = allow_symlinks

        # Precompute some private values only once by using a mock file hasher.
        # None of the arguments used to build the hasher are used.
        hasher = sharded_hasher_factory(pathlib.Path(), 0, 1)
        self._shard_size = hasher.shard_size

    @override
    def serialize(
        self,
        model_path: pathlib.Path,
        *,
        ignore_paths: Iterable[pathlib.Path] = frozenset(),
    ) -> manifest.Manifest:
        """Serializes the model given by the `model_path` argument.

        Args:
            model_path: The path to the model.
            ignore_paths: The paths to ignore during serialization. If a
              provided path is a directory, all children of the directory are
              ignored.

        Returns:
            The model's serialized `manifest.Manifest`

        Raises:
            ValueError: The model contains a symbolic link, but the serializer
              was not initialized with `allow_symlinks=True`.
        """
        shards = []
        # TODO: github.com/sigstore/model-transparency/issues/200 - When
        # Python3.12 is the minimum supported version, the glob can be replaced
        # with `pathlib.Path.walk` for a clearer interface, and some speed
        # improvement.
        for path in itertools.chain((model_path,), model_path.glob("**/*")):
            serialize_by_file.check_file_or_directory(
                path, allow_symlinks=self._allow_symlinks
            )
            if path.is_file() and not serialize_by_file._ignored(
                path, ignore_paths
            ):
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

        return self._build_manifest(manifest_items)

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

    @abc.abstractmethod
    def _build_manifest(
        self, items: Iterable[manifest.ShardedFileManifestItem]
    ) -> manifest.Manifest:
        """Builds an itemized manifest from a given list of items.

        Every subclass needs to implement this method to determine the format of
        the manifest.
        """
        pass


class ManifestSerializer(ShardedFilesSerializer):
    """Model serializers that produces an itemized manifest, at shard level.

    Since the manifest lists each item individually, this will also enable
    support for incremental updates (to be added later).
    """

    @override
    def serialize(
        self,
        model_path: pathlib.Path,
        *,
        ignore_paths: Iterable[pathlib.Path] = frozenset(),
    ) -> manifest.ShardLevelManifest:
        """Serializes the model given by the `model_path` argument.

        The only reason for the override is to change the return type, to be
        more restrictive. This is to signal that the only manifests that can be
        returned are `manifest.ShardLevelManifest` instances.

        Args:
            model_path: The path to the model.
            ignore_paths: The paths to ignore during serialization. If a
              provided path is a directory, all children of the directory are
              ignored.

        Returns:
            The model's serialized `manifest.ShardLevelManifest`

        Raises:
            ValueError: The model contains a symbolic link, but the serializer
              was not initialized with `allow_symlinks=True`.
        """
        return cast(
            manifest.ShardLevelManifest,
            super().serialize(model_path, ignore_paths=ignore_paths),
        )

    @override
    def _build_manifest(
        self, items: Iterable[manifest.ShardedFileManifestItem]
    ) -> manifest.ShardLevelManifest:
        return manifest.ShardLevelManifest(items)


class DigestSerializer(ShardedFilesSerializer):
    """Serializer for a model that performs a traversal of the model directory.

    This serializer produces a single hash for the entire model.
    """

    def __init__(
        self,
        file_hasher_factory: Callable[
            [pathlib.Path, int, int], file.ShardedFileHasher
        ],
        merge_hasher: hashing.StreamingHashEngine,
        *,
        max_workers: Optional[int] = None,
        allow_symlinks: bool = False,
    ):
        """Initializes an instance to serialize a model with this serializer.

        Args:
            hasher_factory: A callable to build the hash engine used to hash
              every shard of the files in the model. Because each shard is
              processed in parallel, every thread needs to call the factory to
              start hashing. The arguments are the file, and the endpoints of
              the shard.
            merge_hasher: A `hashing.StreamingHashEngine` instance used to merge
              individual file shard digests to compute an aggregate digest.
            max_workers: Maximum number of workers to use in parallel. Default
              is to defer to the `concurent.futures` library.
            allow_symlinks: Controls whether symbolic links are included. If a
              symlink is present but the flag is `False` (default) the
              serialization would raise an error.
        """
        super().__init__(
            file_hasher_factory,
            max_workers=max_workers,
            allow_symlinks=allow_symlinks,
        )
        self._merge_hasher = merge_hasher

    @override
    def serialize(
        self,
        model_path: pathlib.Path,
        *,
        ignore_paths: Iterable[pathlib.Path] = frozenset(),
    ) -> manifest.DigestManifest:
        """Serializes the model given by the `model_path` argument.

        The only reason for the override is to change the return type, to be
        more restrictive. This is to signal that the only manifests that can be
        returned are `manifest.DigestManifest` instances.

        Args:
            model_path: The path to the model.
            ignore_paths: The paths to ignore during serialization. If a
              provided path is a directory, all children of the directory are
              ignored.

        Returns:
            The model's serialized `manifest.DigestManifest`

        Raises:
            ValueError: The model contains a symbolic link, but the serializer
              was not initialized with `allow_symlinks=True`.
        """
        return cast(
            manifest.DigestManifest,
            super().serialize(model_path, ignore_paths=ignore_paths),
        )

    @override
    def _build_manifest(
        self, items: Iterable[manifest.ShardedFileManifestItem]
    ) -> manifest.DigestManifest:
        self._merge_hasher.reset()

        for item in sorted(items, key=lambda i: (i.path, i.start, i.end)):
            header = _build_header(
                name=item.path.name, start=item.start, end=item.end
            )
            self._merge_hasher.update(header)
            self._merge_hasher.update(item.digest.digest_value)

        digest = self._merge_hasher.compute()
        return manifest.DigestManifest(digest)
