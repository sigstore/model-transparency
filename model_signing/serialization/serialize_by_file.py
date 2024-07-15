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

"""Model serializers that operated at file level granularity."""

import base64
import concurrent.futures
import pathlib
from typing import Callable, Iterable
from typing_extensions import override

from model_signing.hashing import file
from model_signing.hashing import hashing
from model_signing.manifest import manifest
from model_signing.serialization import serialization


def check_file_or_directory(path: pathlib.Path) -> None:
    """Checks that the given path is either a file or a directory.

    There is no support for sockets, pipes, or any other operating system
    concept abstracted as a file.

    Furthermore, this would raise if the path is a broken symlink, if it doesn't
    exists or if there are permission errors.

    Args:
        path: The path to check.

    Raises:
        ValueError: The path is neither a file or a directory.
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
) -> bytes:
    """Builds a header to encode a path with given name and type.

    Args:
        entry_name: The name of the entry to build the header for.
        entry_type: The type of the entry (file or directory).

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
    # Note: empty string at the end, to terminate header with a "."
    return b".".join([encoded_type, encoded_name, b""])


class DFSSerializer(serialization.Serializer):
    """Serializer for a model that performs a traversal of the model directory.

    This serializer produces a single hash for the entire model. If the model is
    a file, the hash is the digest of the file. If the model is a directory, we
    perform a depth-first traversal of the directory, hash each individual files
    and aggregate the hashes together.
    """

    def __init__(
        self,
        file_hasher: file.SimpleFileHasher,
        merge_hasher_factory: Callable[[], hashing.StreamingHashEngine],
    ):
        """Initializes an instance to serialize a model with this serializer.

        Args:
            hasher: The hash engine used to hash the individual files.
            merge_hasher_factory: A callable that returns a
              `hashing.StreamingHashEngine` instance used to merge individual
              file digests to compute an aggregate digest.
        """
        self._file_hasher = file_hasher
        self._merge_hasher_factory = merge_hasher_factory

    @override
    def serialize(self, model_path: pathlib.Path) -> manifest.DigestManifest:
        # TODO: github.com/sigstore/model-transparency/issues/196 - Add checks
        # to exclude symlinks if desired.
        check_file_or_directory(model_path)

        if model_path.is_file():
            self._file_hasher.set_file(model_path)
            return manifest.DigestManifest(self._file_hasher.compute())

        return manifest.DigestManifest(self._dfs(model_path))

    def _dfs(self, directory: pathlib.Path) -> hashing.Digest:
        # TODO: github.com/sigstore/model-transparency/issues/196 - Add support
        # for excluded files.
        children = sorted([x for x in directory.iterdir()])

        hasher = self._merge_hasher_factory()
        for child in children:
            check_file_or_directory(child)

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
        check_file_or_directory(model_path)

        paths = []
        if model_path.is_file():
            paths.append(model_path)
        else:
            # TODO: github.com/sigstore/model-transparency/issues/200 - When
            # Python3.12 is the minimum supported version, this can be replaced
            # with `pathlib.Path.walk` for a clearer interface, and some speed
            # improvement.
            for path in model_path.glob("**/*"):
                check_file_or_directory(path)
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
