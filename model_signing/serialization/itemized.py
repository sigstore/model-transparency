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

"""Model serializers that build an itemized manifest."""

from collections.abc import Iterable
import concurrent.futures
import pathlib
from typing import Callable
from typing_extensions import override

from model_signing.hashing import file
from model_signing.manifest import manifest
from model_signing.serialization import dfs
from model_signing.serialization import serialization


class FilesSerializer(serialization.Serializer):
    """Model serializers that produces an itemized manifest, at file level.

    Traverses the model directory and creates digests for every file found,
    possibly in parallel.

    Since the manifest lists each item individually, this will also enable
    support for incremental updates (to be added later).
    """

    def __init__(
        self,
        file_hasher_factory: Callable[[pathlib.Path], file.FileHasher],
        max_workers: int | None = None,
    ):
        """Initializes an instance to serialize a model with this serializer.

        Args:
            file_hasher_factory: A callable to build the hash engine used to
              hash individual files.
            max_workers: Maximum number of workers to use in parallel. Default
              is to defer to the `concurrent.futures` library.
        """
        self._hasher_factory = file_hasher_factory
        self._max_workers = max_workers

    @override
    def serialize(self, model_path: pathlib.Path) -> manifest.FileLevelManifest:
        # TODO: github.com/sigstore/model-transparency/issues/196 - Add checks
        # to exclude symlinks if desired.
        dfs.check_file_or_directory(model_path)

        paths = []
        if model_path.is_file():
            paths.append(model_path)
        else:
            # TODO: github.com/sigstore/model-transparency/issues/200 - When
            # Python3.12 is the minimum supported version, this can be replaced
            # with `pathlib.Path.walk` for a clearer interface, and some speed
            # improvement.
            for path in model_path.glob("**/*"):
                dfs.check_file_or_directory(path)
                if path.is_file():
                    paths.append(path)

        manifest_items = []
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self._max_workers
        ) as tpe:
            futures = [
                tpe.submit(self._compute_hash, model_path, path)
                for path in paths
            ]
            for future in concurrent.futures.as_completed(futures):
                manifest_items.append(future.result())

        return self._build_manifest(manifest_items)

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

    def _build_manifest(
        self, items: Iterable[manifest.FileManifestItem]
    ) -> manifest.FileLevelManifest:
        """Builds an itemized manifest from a given list of items.

        Every subclass needs to implement this method to determine the format of
        the manifest.
        """
        return manifest.FileLevelManifest(items)


class ShardedFilesSerializer(serialization.Serializer):
    """Model serializers that produces an itemized manifest, at shard level.

    Traverses the model directory and creates digests for every file found,
    sharding the file in equal shards and computing the digests in parallel.

    Since the manifest lists each item individually, this will also enable
    support for incremental updates (to be added later).
    """

    def __init__(
        self,
        sharded_hasher_factory: Callable[
            [pathlib.Path, int, int], file.ShardedFileHasher
        ],
        max_workers: int | None = None,
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
        """
        self._hasher_factory = sharded_hasher_factory
        self._max_workers = max_workers

        # Precompute some private values only once by using a mock file hasher.
        # None of the arguments used to build the hasher are used.
        hasher = sharded_hasher_factory(pathlib.Path(), 0, 1)
        self._shard_size = hasher.shard_size

    @override
    def serialize(
        self, model_path: pathlib.Path
    ) -> manifest.ShardLevelManifest:
        # TODO: github.com/sigstore/model-transparency/issues/196 - Add checks
        # to exclude symlinks if desired.
        dfs.check_file_or_directory(model_path)

        shards = []
        if model_path.is_file():
            shards.extend(self._get_shards(model_path))
        else:
            # TODO: github.com/sigstore/model-transparency/issues/200 - When
            # Python3.12 is the minimum supported version, this can be replaced
            # with `pathlib.Path.walk` for a clearer interface, and some speed
            # improvement.
            for path in model_path.glob("**/*"):
                dfs.check_file_or_directory(path)
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

        return self._build_manifest(manifest_items)

    def _get_shards(
        self, path: pathlib.Path
    ) -> list[tuple[pathlib.Path, int, int]]:
        """Determines the shards of a given file path."""
        shards = []
        path_size = path.stat().st_size
        if path_size > 0:
            start = 0
            for end in dfs.endpoints(self._shard_size, path_size):
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

    def _build_manifest(
        self, items: Iterable[manifest.ShardedFileManifestItem]
    ) -> manifest.ShardLevelManifest:
        """Builds an itemized manifest from a given list of items.

        Every subclass needs to implement this method to determine the format of
        the manifest.
        """
        return manifest.ShardLevelManifest(items)
