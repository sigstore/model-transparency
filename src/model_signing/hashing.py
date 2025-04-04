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
from typing import Literal, Optional, Union

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
if sys.version_info >= (3, 10):
    from typing import TypeAlias
else:
    from typing_extensions import TypeAlias


# Type alias to support `os.PathLike`, `str` and `bytes` objects in the API
# When Python 3.12 is the minimum supported version we can use `type`
# When Python 3.11 is the minimum supported version we can use `|`
PathLike: TypeAlias = Union[str, bytes, os.PathLike]


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
    generate the hash for every object in the model. We currently support SHA256
    and BLAKE2, with SHA256 being the default.

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

    def hash(self, model_path: PathLike) -> manifest.Manifest:
        """Hashes a model using the current configuration."""
        ignored_paths = [path for path in self._ignored_paths]
        if self._ignore_git_paths:
            ignored_paths.extend(
                [".git/", ".gitattributes", ".github/", ".gitignore"]
            )

        return self._serializer.serialize(
            pathlib.Path(model_path), ignore_paths=ignored_paths
        )

    def _build_stream_hasher(
        self, hashing_algorithm: Literal["sha256", "blake2"] = "sha256"
    ) -> hashing.StreamingHashEngine:
        """Builds a streaming hasher from a constant string.

        Args:
            hashing_algorithm: The hashing algorithm to use.

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
    ) -> Callable[[pathlib.Path], io.SimpleFileHasher]:
        """Builds the hasher factory for a serialization by file.

        Args:
            hashing_algorithm: The hashing algorithm to use to hash a file.
            chunk_size: The amount of file to read at once. Default is 1MB. A
              special value of 0 signals to attempt to read everything in a
              single call.

        Returns:
            The hasher factory that should be used by the active serialization
            method.
        """

        def _factory(path: pathlib.Path) -> io.SimpleFileHasher:
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
        hashing_algorithm: Literal["sha256", "blake2"] = "sha256",
        chunk_size: int = 1048576,
        max_workers: Optional[int] = None,
        allow_symlinks: bool = False,
    ) -> Self:
        """Configures serialization to build a manifest of (file, hash) pairs.

        The serialization method in this configuration is changed to one where
        every file in the model is paired with its digest and a manifest
        containing all these pairings is being built.

        Args:
            hashing_algorithm: The hashing algorithm to use to hash a file.
            chunk_size: The amount of file to read at once. Default is 1MB. A
              special value of 0 signals to attempt to read everything in a
              single call.
            max_workers: Maximum number of workers to use in parallel. Default
              is to defer to the `concurrent.futures` library to select the best
              value for the current machine.
            allow_symlinks: Controls whether symbolic links are included. If a
              symlink is present but the flag is `False` (default) the
              serialization would raise an error.

        Returns:
            The new hashing configuration with the new serialization method.
        """
        self._serializer = file.Serializer(
            self._build_file_hasher_factory(hashing_algorithm, chunk_size),
            max_workers=max_workers,
            allow_symlinks=allow_symlinks,
        )
        return self

    def use_shard_serialization(
        self,
        *,
        hashing_algorithm: Literal["sha256", "blake2"] = "sha256",
        chunk_size: int = 1048576,
        shard_size: int = 1_000_000_000,
        max_workers: Optional[int] = None,
        allow_symlinks: bool = False,
    ) -> Self:
        """Configures serialization to build a manifest of (shard, hash) pairs.

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

        Returns:
            The new hashing configuration with the new serialization method.
        """
        self._serializer = file_shard.Serializer(
            self._build_sharded_file_hasher_factory(
                hashing_algorithm, chunk_size, shard_size
            ),
            max_workers=max_workers,
            allow_symlinks=allow_symlinks,
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
        self._ignored_paths = frozenset({pathlib.Path(p) for p in paths})
        self._ignore_git_paths = ignore_git_paths
        return self
