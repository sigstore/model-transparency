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

"""High level API for the hashing interface of `model_signing` library.

Hashing is used both for signing and verification and users should ensure that
the same configuration is used in both cases.

The module could also be used to just hash a single model, without signing it:

```python
model_signing.hashing.hash(model_path)
```

This module allows setting up the hashing configuration to a single variable and
then sharing it between signing and verification.

```python
hashing_config = model_signing.hashing.Config().set_ignored_paths(
    paths=["README.md"], ignore_git_paths=True
)

signing_config = (
    model_signing.signing.Config()
    .use_elliptic_key_signer(private_key="key")
    .set_hashing_config(hashing_config)
)

verifying_config = (
    model_signing.verifying.Config()
    .use_elliptic_key_verifier(public_key="key.pub")
    .set_hashing_config(hashing_config)
)
```

The API defined here is stable and backwards compatible.
"""

from collections.abc import Callable, Iterable
import os
import pathlib
import sys
from typing import Literal

import blake3

from model_signing import manifest
from model_signing._hashing import hashing
from model_signing._hashing import io
from model_signing._hashing import memory
from model_signing._serialization import file
from model_signing._serialization import file_shard


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


# `TypeAlias` only exists from Python 3.10
# `TypeAlias` is deprecated in Python 3.12 in favor of `type`
from typing import TypeAlias


# Type alias to support `os.PathLike`, `str` and `bytes` objects in the API
# When Python 3.12 is the minimum supported version we can use `type`
# When Python 3.11 is the minimum supported version we can use `|`
PathLike: TypeAlias = str | bytes | os.PathLike


def hash(model_path: PathLike) -> manifest.Manifest:
    """Hashes a model using the default configuration.

    Hashing is the shared part between signing and verification and is also
    expected to be the slowest component. When serializing a model, we need to
    spend time proportional to the model size on disk.

    This method returns a "manifest" of the model. A manifest is a collection of
    every object in the model, paired with the corresponding hash. Currently, we
    consider an object in the model to be either a file or a shard of the file.
    Large models with large files will be hashed much faster when every shard is
    hashed in parallel, at the cost of generating a larger payload for the
    signature. In future releases we could support hashing individual tensors or
    tensor slices for further speed optimizations for very large models.

    Args:
        model_path: The path to the model to hash.

    Returns:
        A manifest of the hashed model.
    """
    return Config().hash(model_path)


class Config:
    """Configuration to use when hashing models.

    Hashing is the shared part between signing and verification and is also
    expected to be the slowest component. When serializing a model, we need to
    spend time proportional to the model size on disk.

    Hashing builds a "manifest" of the model. A manifest is a collection of
    every object in the model, paired with the corresponding hash. Currently, we
    consider an object in the model to be either a file or a shard of the file.
    Large models with large files will be hashed much faster when every shard is
    hashed in parallel, at the cost of generating a larger payload for the
    signature. In future releases we could support hashing individual tensors or
    tensor slices for further speed optimizations for very large models.

    This configuration class supports configuring the hashing granularity. By
    default, we hash at file level granularity.

    This configuration class also supports configuring the hash method used to
    generate the hash for every object in the model. We currently support
    SHA256, BLAKE2, and BLAKE3, with SHA256 being the default.

    This configuration class also supports configuring which paths from the
    model directory should be ignored. These are files that doesn't impact the
    behavior of the model, or files that won't be distributed with the model. By
    default, only files that are associated with a git repository (`.git`,
    `.gitattributes`, `.gitignore`, etc.) are ignored.
    """

    def __init__(self):
        """Initializes the default configuration for hashing."""
        self._ignored_paths = frozenset()
        self._ignore_git_paths = True
        self.use_file_serialization()
        self._allow_symlinks = False

    def hash(
        self,
        model_path: PathLike,
        *,
        files_to_hash: Iterable[PathLike] | None = None,
    ) -> manifest.Manifest:
        """Hashes a model using the current configuration."""
        # All paths in ``_ignored_paths`` are expected to be relative to the
        # model directory. Join them to ``model_path`` and ensure they do not
        # escape it.
        model_path = pathlib.Path(model_path)
        ignored_paths = []
        for p in self._ignored_paths:
            full = model_path / p
            try:
                full.relative_to(model_path)
            except ValueError:
                continue
            ignored_paths.append(full)

        if self._ignore_git_paths:
            ignored_paths.extend(
                [
                    model_path / p
                    for p in [
                        ".git/",
                        ".gitattributes",
                        ".github/",
                        ".gitignore",
                    ]
                ]
            )

        self._serializer.set_allow_symlinks(self._allow_symlinks)

        return self._serializer.serialize(
            pathlib.Path(model_path),
            ignore_paths=ignored_paths,
            files_to_hash=files_to_hash,
        )

    def _build_stream_hasher(
        self,
        hashing_algorithm: Literal["sha256", "blake2", "blake3"] = "sha256",
    ) -> hashing.StreamingHashEngine:
        """Builds a streaming hasher from a constant string.

        Args:
            hashing_algorithm: The hashing algorithm to use.

        Returns:
            An instance of the requested hasher.
        """
        match hashing_algorithm:
            case "sha256":
                return memory.SHA256()
            case "blake2":
                return memory.BLAKE2()
            case "blake3":
                return memory.BLAKE3()
            case _:
                raise ValueError(
                    f"Unsupported hashing method {hashing_algorithm}"
                )

    def _build_file_hasher_factory(
        self,
        hashing_algorithm: Literal["sha256", "blake2", "blake3"] = "sha256",
        chunk_size: int = 1048576,
        max_workers: int | None = None,
    ) -> Callable[[pathlib.Path], io.FileHasher]:
        """Builds the hasher factory for a serialization by file.

        Args:
            hashing_algorithm: The hashing algorithm to use to hash a file.
            chunk_size: The amount of file to read at once. Default is 1MB. A
              special value of 0 signals to attempt to read everything in a
              single call. This is ignored for BLAKE3.
            max_workers: Maximum number of workers to use in parallel. Defaults
              to the number of logical cores. Only relevant for BLAKE3.

        Returns:
            The hasher factory that should be used by the active serialization
            method.
        """
        if max_workers is None:
            max_workers = blake3.blake3.AUTO

        def _factory(path: pathlib.Path) -> io.FileHasher:
            if hashing_algorithm == "blake3":
                return io.Blake3FileHasher(path, max_threads=max_workers)
            hasher = self._build_stream_hasher(hashing_algorithm)
            return io.SimpleFileHasher(path, hasher, chunk_size=chunk_size)

        return _factory

    def _build_sharded_file_hasher_factory(
        self,
        hashing_algorithm: Literal["sha256", "blake2"] = "sha256",
        chunk_size: int = 1048576,
        shard_size: int = 1_000_000_000,
    ) -> Callable[[pathlib.Path, int, int], io.ShardedFileHasher]:
        """Builds the hasher factory for a serialization by file shards.

        This is not recommended for BLAKE3 because it is not necessary. BLAKE3
        already operates in parallel.

        Args:
            hashing_algorithm: The hashing algorithm to use to hash a shard.
            chunk_size: The amount of file to read at once. Default is 1MB. A
              special value of 0 signals to attempt to read everything in a
              single call.
            shard_size: The size of a file shard. Default is 1 GB.

        Returns:
            The hasher factory that should be used by the active serialization
            method.
        """

        def _factory(
            path: pathlib.Path, start: int, end: int
        ) -> io.ShardedFileHasher:
            hasher = self._build_stream_hasher(hashing_algorithm)
            return io.ShardedFileHasher(
                path,
                hasher,
                start=start,
                end=end,
                chunk_size=chunk_size,
                shard_size=shard_size,
            )

        return _factory

    def use_file_serialization(
        self,
        *,
        hashing_algorithm: Literal["sha256", "blake2", "blake3"] = "sha256",
        chunk_size: int = 1048576,
        max_workers: int | None = None,
        allow_symlinks: bool = False,
        ignore_paths: Iterable[pathlib.Path] = frozenset(),
    ) -> Self:
        """Configures serialization to build a manifest of (file, hash) pairs.

        The serialization method in this configuration is changed to one where
        every file in the model is paired with its digest and a manifest
        containing all these pairings is being built.

        Args:
            hashing_algorithm: The hashing algorithm to use to hash a file.
            chunk_size: The amount of file to read at once. Default is 1MB. A
              special value of 0 signals to attempt to read everything in a
              single call. Ignored for BLAKE3.
            max_workers: Maximum number of workers to use in parallel. Default
              is to defer to the `concurrent.futures` library to select the best
              value for the current machine, or the number of logical cores
              when doing BLAKE3 hashing. When reading files off of slower
              hardware like an HDD rather than an SSD, and using BLAKE3,
              setting max_workers to 1 may improve performance.
            allow_symlinks: Controls whether symbolic links are included. If a
              symlink is present but the flag is `False` (default) the
              serialization would raise an error.

        Returns:
            The new hashing configuration with the new serialization method.
        """
        self._serializer = file.Serializer(
            self._build_file_hasher_factory(
                hashing_algorithm, chunk_size, max_workers
            ),
            max_workers=max_workers,
            allow_symlinks=allow_symlinks,
            ignore_paths=ignore_paths,
        )
        return self

    def use_shard_serialization(
        self,
        *,
        hashing_algorithm: Literal["sha256", "blake2", "blake3"] = "sha256",
        chunk_size: int = 1048576,
        shard_size: int = 1_000_000_000,
        max_workers: int | None = None,
        allow_symlinks: bool = False,
        ignore_paths: Iterable[pathlib.Path] = frozenset(),
    ) -> Self:
        """Configures serialization to build a manifest of (shard, hash) pairs.

        For BLAKE3 this is equivalent to not sharding. Sharding is bypassed
        because BLAKE3 already operates in parallel. This means the chunk_size
        and shard_size args are ignored.

        The serialization method in this configuration is changed to one where
        every file in the model is sharded in equal sized shards, every shard is
        paired with its digest and a manifest containing all these pairings is
        being built.

        Args:
            hashing_algorithm: The hashing algorithm to use to hash a shard.
            chunk_size: The amount of file to read at once. Default is 1MB. A
              special value of 0 signals to attempt to read everything in a
              single call.
            shard_size: The size of a file shard. Default is 1 GB.
            max_workers: Maximum number of workers to use in parallel. Default
              is to defer to the `concurrent.futures` library to select the best
              value for the current machine.
            allow_symlinks: Controls whether symbolic links are included. If a
              symlink is present but the flag is `False` (default) the
              serialization would raise an error.
            ignore_paths: Paths of files to ignore.

        Returns:
            The new hashing configuration with the new serialization method.
        """
        if hashing_algorithm == "blake3":
            return self.use_file_serialization(
                hashing_algorithm=hashing_algorithm,
                chunk_size=chunk_size,
                max_workers=max_workers,
                allow_symlinks=allow_symlinks,
                ignore_paths=ignore_paths,
            )

        self._serializer = file_shard.Serializer(
            self._build_sharded_file_hasher_factory(
                hashing_algorithm, chunk_size, shard_size
            ),
            max_workers=max_workers,
            allow_symlinks=allow_symlinks,
            ignore_paths=ignore_paths,
        )
        return self

    def set_ignored_paths(
        self, *, paths: Iterable[PathLike], ignore_git_paths: bool = True
    ) -> Self:
        """Configures the paths to be ignored during serialization of a model.

        If the model is a single file, there are no paths that are ignored. If
        the model is a directory, all paths are considered as relative to the
        model directory, since we never look at files outside of it.

        If an ignored path is a directory, serialization will ignore both the
        path and any of its children.

        Args:
            paths: The paths to ignore.
            ignore_git_paths: Whether to ignore git related paths (default) or
              include them in the signature.

        Returns:
            The new hashing configuration with a new set of ignored paths.
        """
        # Preserve the user-provided relative paths; they are resolved against
        # the model directory later when hashing.
        self._ignored_paths = frozenset(pathlib.Path(p) for p in paths)
        self._ignore_git_paths = ignore_git_paths
        return self

    def add_ignored_paths(
        self, *, model_path: PathLike, paths: Iterable[PathLike]
    ) -> None:
        """Add more paths to ignore to existing set of paths.

        Args:
            model_path: The path to the model
            paths: Additional paths to ignore. All path must be relative to
                   the model directory.
        """
        newset = set(self._ignored_paths)
        model_path = pathlib.Path(model_path)
        for p in paths:
            candidate = pathlib.Path(p)
            full = model_path / candidate
            try:
                full.relative_to(model_path)
            except ValueError:
                continue
            newset.add(candidate)
        self._ignored_paths = newset

    def set_allow_symlinks(self, allow_symlinks: bool) -> Self:
        """Set whether following symlinks is allowed."""
        self._allow_symlinks = allow_symlinks
        return self
