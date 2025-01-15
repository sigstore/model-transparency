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


def check_file_or_directory(
    path: pathlib.Path, *, allow_symlinks: bool = False
) -> None:
    """Checks that the given path is either a file or a directory.

    There is no support for sockets, pipes, or any other operating system
    concept abstracted as a file.

    Furthermore, this would raise if the path is a broken symlink, if it doesn't
    exists or if there are permission errors.

    Args:
        path: The path to check.
        allow_symlinks: Controls whether symbolic links are included. If a
          symlink is present but the flag is `False` (default) the
          serialization would raise an error.

    Raises:
        ValueError: The path is neither a file or a directory, or the path
          is a symlink and `allow_symlinks` is false.
    """
    if not allow_symlinks and path.is_symlink():
        raise ValueError(
            f"Cannot use '{path}' because it is a symlink. This"
            " behavior can be changed with `allow_symlinks`."
        )
    if not (path.is_file() or path.is_dir()):
        raise ValueError(
            f"Cannot use '{path}' as file or directory. It could be a"
            " special file, it could be missing, or there might be a"
            " permission issue."
        )


def _build_header(*, entry_name: str, entry_type: str) -> bytes:
    """Builds a header to encode a path with given name and type.

    Args:
        entry_name: The name of the entry to build the header for.
        entry_type: The type of the entry (file or directory).

    Returns:
        A sequence of bytes that encodes all arguments as a sequence of UTF-8
        bytes. Each argument is separated by dots and the last byte is also a
        dot (so the file digest can be appended unambiguously).
    """
    encoded_type = entry_type.encode("utf-8")
    # Prevent confusion if name has a "." inside by encoding to base64.
    encoded_name = base64.b64encode(entry_name.encode("utf-8"))
    # Note: empty string at the end, to terminate header with a "."
    return b".".join([encoded_type, encoded_name, b""])


def _ignored(path: pathlib.Path, ignore_paths: Iterable[pathlib.Path]) -> bool:
    """Determines if the provided path should be ignored.

    Args:
        path: The path to check.
        ignore_paths: The paths to ignore while serializing a model.

    Returns:
        Whether or not the provided path should be ignored.
    """
    return any(path.is_relative_to(ignore_path) for ignore_path in ignore_paths)


class FilesSerializer(serialization.Serializer):
    """Generic file serializer.

    Traverses the model directory and creates digests for every file found,
    possibly in parallel.

    Subclasses can then create a manifest with these digests, either listing
    them item by item, or combining everything into a single digest.
    """

    def __init__(
        self,
        file_hasher_factory: Callable[[pathlib.Path], file.FileHasher],
        *,
        max_workers: Optional[int] = None,
        allow_symlinks: bool = False,
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
        """
        self._hasher_factory = file_hasher_factory
        self._max_workers = max_workers
        self._allow_symlinks = allow_symlinks

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
        paths = []
        # TODO: github.com/sigstore/model-transparency/issues/200 - When
        # Python3.12 is the minimum supported version, the glob can be replaced
        # with `pathlib.Path.walk` for a clearer interface, and some speed
        # improvement.
        for path in itertools.chain((model_path,), model_path.glob("**/*")):
            check_file_or_directory(path, allow_symlinks=self._allow_symlinks)
            if path.is_file() and not _ignored(path, ignore_paths):
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

    @abc.abstractmethod
    def _build_manifest(
        self, items: Iterable[manifest.FileManifestItem]
    ) -> manifest.Manifest:
        """Builds the manifest representing the serialization of the model."""
        pass


class ManifestSerializer(FilesSerializer):
    """Model serializer that produces an itemized manifest, at file level.

    Since the manifest lists each item individually, this will also enable
    support for incremental updates (to be added later).
    """

    @override
    def serialize(
        self,
        model_path: pathlib.Path,
        *,
        ignore_paths: Iterable[pathlib.Path] = frozenset(),
    ) -> manifest.FileLevelManifest:
        """Serializes the model given by the `model_path` argument.

        The only reason for the override is to change the return type, to be
        more restrictive. This is to signal that the only manifests that can be
        returned are `manifest.FileLevelManifest` instances.

        Args:
            model_path: The path to the model.
            ignore_paths: The paths to ignore during serialization. If a
              provided path is a directory, all children of the directory are
              ignored.

        Returns:
            The model's serialized `manifest.FileLevelManifest`

        Raises:
            ValueError: The model contains a symbolic link, but the serializer
              was not initialized with `allow_symlinks=True`.
        """
        return cast(
            manifest.FileLevelManifest,
            super().serialize(model_path, ignore_paths=ignore_paths),
        )

    @override
    def _build_manifest(
        self, items: Iterable[manifest.FileManifestItem]
    ) -> manifest.FileLevelManifest:
        return manifest.FileLevelManifest(items)


class _FileDigestTree:
    """A tree of files with their digests.

    Every leaf in the tree is a file, paired with its digest. Every intermediate
    node represents a directory. We need to pair every directory with a digest,
    in a bottom-up fashion.
    """

    def __init__(
        self, path: pathlib.PurePath, digest: Optional[hashing.Digest] = None
    ):
        """Builds a node in the digest tree.

        Don't call this from outside of the class. Instead, use `build_tree`.

        Args:
            path: Path included in the node.
            digest: Optional hash of the path. Files must have a digest,
              directories never have one.
        """
        self._path = path
        self._digest = digest
        self._children: list[_FileDigestTree] = []

    @classmethod
    def build_tree(
        cls, items: Iterable[manifest.FileManifestItem]
    ) -> "_FileDigestTree":
        """Builds a tree out of the sequence of manifest items."""
        path_to_node: dict[pathlib.PurePath, _FileDigestTree] = {}

        for file_item in items:
            file = file_item.path
            node = cls(file, file_item.digest)
            for parent in file.parents:
                if parent in path_to_node:
                    parent_node = path_to_node[parent]
                    parent_node._children.append(node)
                    break  # everything else already exists

                parent_node = cls(parent)  # no digest for directories
                parent_node._children.append(node)
                path_to_node[parent] = parent_node
                node = parent_node

        # Handle empty model
        if not path_to_node:
            return cls(pathlib.PurePosixPath())

        return path_to_node[pathlib.PurePosixPath()]

    def get_digest(
        self, hasher_factory: Callable[[], hashing.StreamingHashEngine]
    ) -> hashing.Digest:
        """Returns the digest of this tree of files.

        Args:
            hasher_factory: A callable that returns a
              `hashing.StreamingHashEngine` instance used to merge individual
              digests to compute an aggregate digest.
        """
        hasher = hasher_factory()

        for child in sorted(self._children, key=lambda c: c._path):
            name = child._path.name
            if child._digest is not None:
                header = _build_header(entry_name=name, entry_type="file")
                hasher.update(header)
                hasher.update(child._digest.digest_value)
            else:
                header = _build_header(entry_name=name, entry_type="dir")
                hasher.update(header)
                digest = child.get_digest(hasher_factory)
                hasher.update(digest.digest_value)

        return hasher.compute()


class DigestSerializer(FilesSerializer):
    """Serializer for a model that performs a traversal of the model directory.

    This serializer produces a single hash for the entire model. If the model is
    a file, the hash is the digest of the file. If the model is a directory, we
    perform a depth-first traversal of the directory, hash each individual files
    and aggregate the hashes together.

    Currently, this has a different initialization than `FilesSerializer`, but
    this will likely change in a subsequent change. Similarly, currently, this
    only supports one single worker, but this will change in the future.
    """

    def __init__(
        self,
        file_hasher: file.SimpleFileHasher,
        merge_hasher_factory: Callable[[], hashing.StreamingHashEngine],
        *,
        allow_symlinks: bool = False,
    ):
        """Initializes an instance to serialize a model with this serializer.

        Args:
            hasher: The hash engine used to hash the individual files.
            merge_hasher_factory: A callable that returns a
              `hashing.StreamingHashEngine` instance used to merge individual
              file digests to compute an aggregate digest.
            allow_symlinks: Controls whether symbolic links are included. If a
              symlink is present but the flag is `False` (default) the
              serialization would raise an error.
        """

        def _factory(path: pathlib.Path) -> file.FileHasher:
            file_hasher.set_file(path)
            return file_hasher

        super().__init__(_factory, max_workers=1, allow_symlinks=allow_symlinks)
        self._merge_hasher_factory = merge_hasher_factory

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
        self, items: Iterable[manifest.FileManifestItem]
    ) -> manifest.DigestManifest:
        # Note: we do several computations here to try and match the old
        # behavior but these would be simplified in the future. Since we are
        # defining the hashing behavior, we can freely change this.

        # If the model is just one file, return the hash of the file.
        # A model is a file if we have one item only and its path is empty.
        items = list(items)
        if len(items) == 1 and not items[0].path.name:
            return manifest.DigestManifest(items[0].digest)

        # Otherwise, build a tree of files and compute the digests.
        tree = _FileDigestTree.build_tree(items)
        digest = tree.get_digest(self._merge_hasher_factory)
        return manifest.DigestManifest(digest)
