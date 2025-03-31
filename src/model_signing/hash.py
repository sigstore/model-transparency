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

"""High level API for the hashing interface of model_signing library.

Hashing is used both for signing and verification and users should ensure that
the same configuration is used in both cases.

Users should use this API to hash models (no signing and verification), rather
than using the internals of the library. We guarantee backwards compatibility
only for the API defined in `hash.py`, `sign.py` and `verify.py` at the root
level of the library.
"""

from collections.abc import Callable, Iterable
import os
import pathlib
import sys
from typing import Literal, Optional

from model_signing import manifest
from model_signing._hashing import file
from model_signing._hashing import hashing
from model_signing._hashing import memory
from model_signing._serialization import serialize_by_file
from model_signing._serialization import serialize_by_file_shard


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


def hash(model_path: os.PathLike) -> manifest.Manifest:
    """Hashes a model using the default configuration.

    We use a separate method and configuration for hashing as it needs to be
    common between signing and signature verification. Having thise separate
    also helps with performance testing, as hashing is expected to take the
    largest amount of time (proportional to model size).

    Since we need to be flexible on the serialization format, this returns a
    manifest, instead of just a single digest. The type of returned manifest
    depends on the configuration.

    Args:
        model_path: the path to the model to hash.

    Returns:
        A manifest of the hashed model.
    """
    return Config().hash(model_path)


class Config:
    """Configuration to use when hashing models.

    Hashing a model results in a manifest object. This is a pairing between
    model components (e.g., files, file shards, etc.) and their corresponding
    hash. This configuration class allows selecting the serialization method to
    generate the desired manifest format.

    This configuration class also allows configuring files from within the model
    directory that should be ignored. These are files that doesn't impact the
    behavior of the model, or files that won't be distributed with the model.

    Note that currently this configuration class only supports the main options
    provided by the library. For more granular choices, usage of the lower level
    APIs is recommended.
    """

    def __init__(self):
        """Initializes the default configuration for hashing.

        The default hashing configuration uses SHA256 to compute the digest of
        every file in the model. The resulting manifest is a listing of files
        paired with their hashes. By default, no file is ignored and any
        symbolic link in the model directory results in an error.
        """
        self._ignored_paths = frozenset()
        self._serializer = serialize_by_file.ManifestSerializer(
            self._build_file_hasher_factory(), allow_symlinks=False
        )

    def hash(self, model_path: os.PathLike) -> manifest.Manifest:
        """Hashes a model using the current configuration."""
        return self._serializer.serialize(
            pathlib.Path(model_path), ignore_paths=self._ignored_paths
        )

    def _build_stream_hasher(
        self, hashing_algorithm: Literal["sha256", "blake2"] = "sha256"
    ) -> hashing.StreamingHashEngine:
        """Builds a streaming hasher from a constant string.

        Args:
            hashing_algorithm: the hashing algorithm to use.

        Returns:
            An instance of the requested hasher.
        """
        # TODO: Once Python 3.9 support is deprecated revert to using `match`
        if hashing_algorithm == "sha256":
            return memory.SHA256()
        if hashing_algorithm == "blake2":
            return memory.BLAKE2()

        raise ValueError(f"Unsupported hashing method {hashing_algorithm}")

    def _build_file_hasher_factory(
        self,
        hashing_algorithm: Literal["sha256", "blake2"] = "sha256",
        chunk_size: int = 1048576,
    ) -> Callable[[pathlib.Path], file.SimpleFileHasher]:
        """Builds the hasher factory for a serialization by file.

        Args:
            hashing_algorithm: the hashing algorithm to use to hash a file
            chunk_size: The amount of file to read at once. Default is 1MB. A
              special value of 0 signals to attempt to read everything in a
              single call.

        Returns:
            The hasher factory that should be used by the active serialization
            method.
        """

        def factory(path: pathlib.Path) -> file.SimpleFileHasher:
            hasher = self._build_stream_hasher(hashing_algorithm)
            return file.SimpleFileHasher(path, hasher, chunk_size=chunk_size)

        return factory

    def _build_sharded_file_hasher_factory(
        self,
        hashing_algorithm: Literal["sha256", "blake2"] = "sha256",
        chunk_size: int = 1048576,
        shard_size: int = 1_000_000_000,
    ) -> Callable[[pathlib.Path, int, int], file.ShardedFileHasher]:
        """Builds the hasher factory for a serialization by file shards.

        Args:
            hashing_algorithm: the hashing algorithm to use to hash a file
            chunk_size: The amount of file to read at once. Default is 1MB. A
              special value of 0 signals to attempt to read everything in a
              single call.
            shard_size: The size of a file shard. Default is 1 GB.

        Returns:
            The hasher factory that should be used by the active serialization
            method.
        """
        algorithm = self._build_stream_hasher(hashing_algorithm)

        def factory(
            path: pathlib.Path, start: int, end: int
        ) -> file.ShardedFileHasher:
            return file.ShardedFileHasher(
                path,
                algorithm,
                start=start,
                end=end,
                chunk_size=chunk_size,
                shard_size=shard_size,
            )

        return factory

    def set_serialize_by_file_to_manifest(
        self,
        *,
        hashing_algorithm: Literal["sha256", "blake2"] = "sha256",
        chunk_size: int = 1048576,
        max_workers: Optional[int] = None,
        allow_symlinks: bool = False,
    ) -> Self:
        """Configures serialization to a manifest pairing files with hashes.

        The serialization method in this configuration is changed to one where
        every file in the model is paired with its digest and a manifest
        containing all these pairings is being returned.

        Args:
            hashing_algorithm: the hashing algorithm to use to hash a file
            chunk_size: The amount of file to read at once. Default is 1MB. A
              special value of 0 signals to attempt to read everything in a
              single call.
            max_workers: Maximum number of workers to use in parallel. Default
              is to defer to the `concurrent.futures` library.
            allow_symlinks: Controls whether symbolic links are included. If a
              symlink is present but the flag is `False` (default) the
              serialization would raise an error.

        Returns:
            The new hashing configuration with the new serialization method.
        """
        self._serializer = serialize_by_file.ManifestSerializer(
            self._build_file_hasher_factory(hashing_algorithm, chunk_size),
            max_workers=max_workers,
            allow_symlinks=allow_symlinks,
        )
        return self

    def set_serialize_by_file_shard_to_manifest(
        self,
        *,
        hashing_algorithm: Literal["sha256", "blake2"] = "sha256",
        chunk_size: int = 1048576,
        shard_size: int = 1_000_000_000,
        max_workers: Optional[int] = None,
        allow_symlinks: bool = False,
    ) -> Self:
        """Configures serialization to a manifest of (file shard, hash) pairs.

        The serialization method in this configuration is changed to one where
        every file in the model is sharded in equal sized shards and every shard
        is paired with its digest and a manifest containing all these pairings
        is being returned.

        Args:
            hashing_algorithm: the hashing algorithm to use to hash a file shard
            chunk_size: The amount of file to read at once. Default is 1MB. A
              special value of 0 signals to attempt to read everything in a
              single call.
            shard_size: The size of a file shard. Default is 1 GB.
            max_workers: Maximum number of workers to use in parallel. Default
              is to defer to the `concurrent.futures` library.
            allow_symlinks: Controls whether symbolic links are included. If a
              symlink is present but the flag is `False` (default) the
              serialization would raise an error.

        Returns:
            The new hashing configuration with the new serialization method.
        """
        self._serializer = serialize_by_file_shard.ManifestSerializer(
            self._build_sharded_file_hasher_factory(
                hashing_algorithm, chunk_size, shard_size
            ),
            max_workers=max_workers,
            allow_symlinks=allow_symlinks,
        )
        return self

    def set_ignored_paths(self, paths: Iterable[os.PathLike]) -> Self:
        """Configures the paths to be ignored during serialization of a model.

        If the model is a single file, there are no paths that are ignored. If
        the model is a directory, all paths must be within the model directory.
        If a path to be ignored is absolute, we convert it to a path within the
        model directory during serialization. If the path is relative, it is
        assumed to be relative to the model root.

        If a path is a directory, serialization will ignore both the path and
        any of its children.

        Args:
            paths: the paths to ignore

        Returns:
            The new hashing configuration with a new set of ignored paths.
        """
        self._ignored_paths = frozenset({pathlib.Path(p) for p in paths})
        return self
