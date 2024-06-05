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

"""Model serializers that build a single hash out of a DFS traversal."""

import base64
import concurrent.futures
import pathlib
from typing import Callable, Iterable, TypeAlias
from typing_extensions import override

from model_signing.hashing import file
from model_signing.hashing import hashing
from model_signing.manifest import manifest
from model_signing.serialization import serialization


def _check_file_or_directory(path: pathlib.Path) -> bool:
    """Checks that the given path is either a file or a directory.

    There is no support for sockets, pipes, or any other operating system
    concept abstracted as a file.

    Furthermore, this would return False if the path is a broken symlink, if it
    doesn't exists or if there are permission errors.
    """
    if not (path.is_file() or path.is_dir()):
        raise ValueError(
            f"Cannot use '{path}' as file or directory. It could be a"
            " special file, it could be missing, or there might be a"
            " permission issue."
        )


def _build_header(
    *,
    entry_name: str,
    entry_type: str,
    start: int | None = None,
    end: int | None = None,
) -> bytes:
    """Builds a header to encode a path with given name and type.

    Args:
        entry_name: The name of the entry to build the header for.
        entry_type: The type of the entry (file or directory).
    """
    encoded_type = entry_type.encode("utf-8")
    # Prevent confusion if name has a "." inside by encoding to base64.
    encoded_name = base64.b64encode(entry_name.encode("utf-8"))

    if start is not None and end is not None:
        # Note: make sure to end with a ".".
        encoded_range = f"{start}-{end}.".encode("utf-8")
    else:
        # Note: no "." at end here, it will be added by `join` on return.
        encoded_range = b""

    return b".".join([encoded_type, encoded_name, encoded_range])


class DFSSerializer(serialization.Serializer):
    """Serializer for a model that performs a traversal of the model directory.

    This serializer produces a single hash for the entire model. If the model is
    a file, the hash is the digest of the file. If the model is a directory, we
    perform a depth-first traversal of the directory, hash each individual files
    and aggregate the hashes together.
    """

    def __init__(
        self,
        file_hasher: file.FileHasher,
        merge_hasher_factory: Callable[[], hashing.StreamingHashEngine],
    ):
        """Initializes an instance to hash a file with a specific `HashEngine`.

        Args:
            hasher: The hash engine used to hash the individual files.
            merge_hasher_factory: A callable that returns a
              `hashing.StreamingHashEngine` instance used to merge individual
              file digests to compute an aggregate digest.
        """
        self._file_hasher = file_hasher
        self._merge_hasher_factory = merge_hasher_factory

    @override
    def serialize(self, model_path: pathlib.Path) -> manifest.Manifest:
        # TODO(mihaimaruseac): Add checks to exclude symlinks if desired
        _check_file_or_directory(model_path)

        if model_path.is_file():
            self._file_hasher.set_file(model_path)
            return manifest.DigestManifest(self._file_hasher.compute())

        return manifest.DigestManifest(self._dfs(model_path))

    def _dfs(self, directory: pathlib.Path) -> hashing.Digest:
        # TODO(mihaimaruseac): Add support for excluded files
        children = sorted([x for x in directory.iterdir()])

        hasher = self._merge_hasher_factory()
        for child in children:
            _check_file_or_directory(child)

            if child.is_file():
                header = _build_header(entry_name=child.name, entry_type="file")
                hasher.update(header)
                self._file_hasher.set_file(child)
                digest = self._file_hasher.compute()
                hasher.update(digest.digest_value)
            else:
                header = _build_header(entry_name=child.name, entry_type="dir")
                hasher.update(header)
                digest = self._dfs(child)
                hasher.update(digest.digest_value)

        return hasher.compute()


# Define type aliases for the ShardedDFSSerializer class below.
_SizedPath: TypeAlias = tuple[pathlib.PurePath, str, int]
_ShardSignTask: TypeAlias = tuple[pathlib.PurePath, str, int, int]


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
        """Initializes an instance to hash a file with a specific `HashEngine`.

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
    def serialize(self, model_path: pathlib.Path) -> manifest.Manifest:
        # TODO(mihaimaruseac): Add checks to exclude symlinks if desired
        _check_file_or_directory(model_path)

        if model_path.is_file():
            entries = [model_path]
        else:
            # TODO: When Python3.12 is the minimum supported version, this can
            # be replaced with `pathlib.Path.walk` for a clearer interface.
            entries = sorted(model_path.glob("**/*"))

        sized_paths = self._get_sizes(entries, model_path)
        tasks = self._build_tasks(sized_paths)

        digest_len = self._merge_hasher.digest_size
        digests_buffer = bytearray(len(tasks) * digest_len)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self._max_workers
        ) as tpe:
            futures_dict = {
                tpe.submit(self._hash_task, model_path, task): i
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

    def _get_sizes(
        self, paths: Iterable[pathlib.Path], root_path: pathlib.Path
    ) -> list[_SizedPath]:
        """Computes size and type for all paths which will be hashed.

        Each entry in `paths` is replaced by a triple representing its relative
        path, its type (as a string) and its size. These are the elements needed
        to build the hash.

        For directories, the size is set to 0.

        We don't construct an enum for the type of the entry, because these will
        never escape this class.

        Note that the path component of the return is a `pathlib.PurePath`, so
        operations on it cannot touch the filesystem.
        """
        # TODO(mihaimaruseac): Add support for excluded files
        triples = []
        for path in paths:
            _check_file_or_directory(path)
            if path.is_file():
                path_type = "file"
                path_size = path.stat().st_size
            else:
                path_type = "dir"
                path_size = 0
            relative_path = path.relative_to(root_path)
            triples.append((relative_path, path_type, path_size))
        return triples

    def _build_tasks(
        self, records: Iterable[_SizedPath]
    ) -> list[_ShardSignTask]:
        """Builds the tasks that would hash shards of files in parallel."""
        tasks = []
        for record_path, record_type, record_size in records:
            if record_type == "file":
                start = 0
                for end in _endpoints(self._shard_size, record_size):
                    tasks.append((record_path, record_type, start, end))
                    start = end
            else:
                tasks.append((record_path, record_type, 0, 0))
        return tasks

    def _hash_task(
        self, model_path: pathlib.Path, task: _ShardSignTask
    ) -> bytes:
        """Produces the hash of the file shard included in `task`."""
        task_path, task_type, task_start, task_end = task

        # TODO(mihaimaruseac): Directories don't need to use the file hasher.
        # Rather than starting a process just for them, we should filter these
        # ahead of time, and only use threading for file shards. For now, just
        # return an empty result.
        if task_type == "dir":
            return b""

        # TODO(mihaimaruseac): Similarly, empty files should be hashed outside
        # of a parallel task, to not waste resources.
        if task_start == task_end:
            return b""

        full_path = model_path.joinpath(task_path)
        hasher = self._file_hasher_factory(full_path, task_start, task_end)
        return hasher.compute().digest_value
