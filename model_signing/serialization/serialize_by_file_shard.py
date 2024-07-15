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

import base64
import concurrent.futures
import pathlib
from typing import Callable, Iterable, TypeAlias
from typing_extensions import override

from model_signing.hashing import file
from model_signing.hashing import hashing
from model_signing.manifest import manifest
from model_signing.serialization import serialization
from model_signing.serialization import serialize_by_file


_ShardSignTask: TypeAlias = tuple[pathlib.PurePath, str, int, int]


def _build_header(
    *,
    entry_name: str,
    entry_type: str,
    start: int,
    end: int,
) -> bytes:
    """Builds a header to encode a path with given name and type.

    Args:
        entry_name: The name of the entry to build the header for.
        entry_type: The type of the entry (file or directory).
        start: Offset for the start of the path shard.
        end: Offset for the end of the path shard.

    Returns:
        A sequence of bytes that encodes all arguments as a sequence of UTF-8
        bytes. Each argument is separated by dots and the last byte is also a
        dot (so the file digest can be appended unambiguously).
    """
    # Note: This will get replaced in subsequent change, right now we're just
    # moving existing code around.
    encoded_type = entry_type.encode("utf-8")
    # Prevent confusion if name has a "." inside by encoding to base64.
    encoded_name = base64.b64encode(entry_name.encode("utf-8"))
    encoded_range = f"{start}-{end}".encode("utf-8")
    # Note: empty string at the end, to terminate header with a "."
    return b".".join([encoded_type, encoded_name, encoded_range, b""])


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
    for value in range(step, end, step):
        yield value
    yield end


class ShardedDFSSerializer(serialization.Serializer):
    """DFSSerializer that uses a sharded hash engine to exploit parallelism."""

    def __init__(
        self,
        file_hasher_factory: Callable[
            [pathlib.Path, int, int], file.ShardedFileHasher
        ],
        merge_hasher: hashing.StreamingHashEngine,
        max_workers: int | None = None,
    ):
        """Initializes an instance to serialize a model with this serializer.

        Args:
            hasher_factory: A callable to build the hash engine used to hash
              every shard of the files in the model. Because each shard is
              processed in parallel, every thread needs to call the factory to
              start hashing. The arguments are the file, and the endpoints of
              the shard.
            merge_hasher: A `hashing.StreamingHashEngine` instance used to merge
              individual file digests to compute an aggregate digest.
            max_workers: Maximum number of workers to use in parallel. Default
              is to defer to the `concurent.futures` library.
        """
        self._file_hasher_factory = file_hasher_factory
        self._merge_hasher = merge_hasher
        self._max_workers = max_workers

        # Precompute some private values only once by using a mock file hasher.
        # None of the arguments used to build the hasher are used.
        hasher = file_hasher_factory(pathlib.Path(), 0, 1)
        self._shard_size = hasher.shard_size

    @override
    def serialize(self, model_path: pathlib.Path) -> manifest.DigestManifest:
        # Note: This function currently uses `pathlib.Path.glob` so the DFS
        # expansion relies on the `glob` implementation performing a DFS. We
        # will be truthful again when switching to `pathlib.Path.walk`, after
        # Python 3.12 is the minimum version we support.

        # TODO: github.com/sigstore/model-transparency/issues/196 - Add checks
        # to exclude symlinks if desired.
        serialize_by_file.check_file_or_directory(model_path)

        if model_path.is_file():
            entries = [model_path]
        else:
            # TODO: github.com/sigstore/model-transparency/issues/200 - When
            # Python3.12 is the minimum supported version, this can be replaced
            # with `pathlib.Path.walk` for a clearer interface, and some speed
            # improvement.
            entries = sorted(model_path.glob("**/*"))

        tasks = self._convert_paths_to_tasks(entries, model_path)

        digest_len = self._merge_hasher.digest_size
        digests_buffer = bytearray(len(tasks) * digest_len)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self._max_workers
        ) as tpe:
            futures_dict = {
                tpe.submit(self._perform_hash_task, model_path, task): i
                for i, task in enumerate(tasks)
            }
            for future in concurrent.futures.as_completed(futures_dict):
                i = futures_dict[future]
                task_digest = future.result()

                task_path, task_type, task_start, task_end = tasks[i]
                header = _build_header(
                    entry_name=task_path.name,
                    entry_type=task_type,
                    start=task_start,
                    end=task_end,
                )
                self._merge_hasher.reset(header)
                self._merge_hasher.update(task_digest)
                digest = self._merge_hasher.compute().digest_value

                start = i * digest_len
                end = start + digest_len
                digests_buffer[start:end] = digest

        self._merge_hasher.reset(digests_buffer)
        return manifest.DigestManifest(self._merge_hasher.compute())

    def _convert_paths_to_tasks(
        self, paths: Iterable[pathlib.Path], root_path: pathlib.Path
    ) -> list[_ShardSignTask]:
        """Returns the tasks that would hash shards of files in parallel.

        Every file in `paths` is replaced by a set of tasks. Each task computes
        the digest over a shard of the file. Directories result in a single
        task, just to compute a digest over a header.

        To differentiate between (empty) files and directories with the same
        name, every task needs to also include a header. The header needs to
        include relative path to the model root, as we want to obtain the same
        digest if the model is moved.

        We don't construct an enum for the type of the entry, because these will
        never escape this class.

        Note that the path component of the tasks is a `pathlib.PurePath`, so
        operations on it cannot touch the filesystem.
        """
        # TODO: github.com/sigstore/model-transparency/issues/196 - Add support
        # for excluded files.

        tasks = []
        for path in paths:
            serialize_by_file.check_file_or_directory(path)
            relative_path = path.relative_to(root_path)

            if path.is_file():
                path_size = path.stat().st_size
                start = 0
                for end in _endpoints(self._shard_size, path_size):
                    tasks.append((relative_path, "file", start, end))
                    start = end
            else:
                tasks.append((relative_path, "dir", 0, 0))

        return tasks

    def _perform_hash_task(
        self, model_path: pathlib.Path, task: _ShardSignTask
    ) -> bytes:
        """Produces the hash of the file shard included in `task`."""
        task_path, task_type, task_start, task_end = task

        # TODO: github.com/sigstore/model-transparency/issues/197 - Directories
        # don't need to use the file hasher.  Rather than starting a process
        # just for them, we should filter these ahead of time, and only use
        # threading for file shards. For now, just return an empty result.
        if task_type == "dir":
            return b""

        # TODO: github.com/sigstore/model-transparency/issues/197 - Similarly,
        # empty files should be hashed outside of a parallel task, to not waste
        # resources.
        if task_start == task_end:
            return b""

        full_path = model_path.joinpath(task_path)
        hasher = self._file_hasher_factory(full_path, task_start, task_end)
        return hasher.compute().digest_value


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
        serialize_by_file.check_file_or_directory(model_path)

        shards = []
        if model_path.is_file():
            shards.extend(self._get_shards(model_path))
        else:
            # TODO: github.com/sigstore/model-transparency/issues/200 - When
            # Python3.12 is the minimum supported version, this can be replaced
            # with `pathlib.Path.walk` for a clearer interface, and some speed
            # improvement.
            for path in model_path.glob("**/*"):
                serialize_by_file.check_file_or_directory(path)
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

    def _build_manifest(
        self, items: Iterable[manifest.ShardedFileManifestItem]
    ) -> manifest.ShardLevelManifest:
        """Builds an itemized manifest from a given list of items.

        Every subclass needs to implement this method to determine the format of
        the manifest.
        """
        return manifest.ShardLevelManifest(items)
