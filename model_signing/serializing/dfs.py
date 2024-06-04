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

import pathlib
from typing import Callable
from typing_extensions import override

from model_signing.hashing import file
from model_signing.hashing import hashing
from model_signing.manifest import manifest
from model_signing.serializing import serializing


def _check_file_or_directory(path: pathlib.Path) -> bool:
    """Checks that the given path is either a file or a directory.

    There is no support for sockets, pipes, or any other operating system
    concept abstracted as a file.

    Furthermore, this would return False if the path is a broken symlink, if it
    doesn't exists or if there are permission errors.
    """
    return path.is_file() or path.is_dir()


def _build_header(*, entry_name: str, entry_type: str) -> bytes:
    """Builds a header to encode a path with given name and type.

    Args:
        entry_name: The name of the entry to build the header for.
        entry_type: The type of the entry (file or directory).
    """
    encoded_type = entry_type.encode("utf-8")
    encoded_name = entry_name.encode("utf-8")
    # Note: make sure to end with a ".".
    return b".".join([encoded_type, encoded_name, b""])


class DFSSerializer(serializing.Serializer):
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
        if not _check_file_or_directory(model_path):
            raise ValueError(
                f"Cannot use '{model_path}' as file or directory. It could be a"
                " special file, it could be missing, or there might be a"
                " permission issue."
            )

        if model_path.is_file():
            self._file_hasher.set_file(model_path)
            return manifest.DigestManifest(self._file_hasher.compute())

        return manifest.DigestManifest(self._dfs(model_path))

    def _dfs(self, directory: pathlib.Path) -> hashing.Digest:
        # TODO(mihaimaruseac): Add support for excluded files
        children = sorted([x for x in directory.iterdir()])

        hasher = self._merge_hasher_factory()
        for child in children:
            if not _check_file_or_directory(child):
                raise ValueError(
                    f"Cannot use '{child}' as file or directory. It could be a"
                    " special file, it could be missing, or there might be a"
                    " permission issue."
                )

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
