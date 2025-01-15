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

"""Machinery for computing digests for a single file.

Example usage for `SimpleFileHasher`:
```python
>>> with open("/tmp/file", "w") as f:
...     f.write("abcd")
>>> hasher = SimpleFileHasher("/tmp/file", SHA256())
>>> digest = hasher.compute()
>>> digest.digest_hex
'88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589'
```

Example usage for `ShardedFileHasher`, reading only the second part of a file:
```python
>>> with open("/tmp/file", "w") as f:
...     f.write("0123abcd")
>>> hasher = ShardedFileHasher("/tmp/file", SHA256(), start=4, end=8)
>>> digest = hasher.compute()
>>> digest.digest_hex
'88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589'
```

Example usage for `OpenedFileHasher`:
```python
>>> with open("/tmp/file", "w") as f:
...     f.write("abcd")
>>> with open("/tmp/file", "rb") as f:
...     hasher = OpenedFileHasher(f)
...     digest = hasher.compute()
>>> digest.digest_hex
'88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589'
```
"""

import hashlib
import pathlib
import sys
from typing import BinaryIO, Optional

from typing_extensions import override

from model_signing.hashing import hashing


class FileHasher(hashing.HashEngine):
    """Generic file hash engine.

    This class is intentionally empty (and abstract, via inheritance) to be used
    only as a type annotation (to signal that API expects a hasher capable of
    hashing files, instead of any `HashEngine` instance).
    """

    pass


class SimpleFileHasher(FileHasher):
    """Simple file hash engine that computes the digest iteratively.

    To compute the hash of a file, we read the file exactly once, including for
    very large files that don't fit in memory. Files are read in chunks and each
    chunk is passed to the `update` method of an inner
    `hashing.StreamingHashEngine`, instance. This ensures that the file digest
    will not change even if the chunk size changes. As such, we can dynamically
    determine an optimal value for the chunk argument.
    """

    def __init__(
        self,
        file: pathlib.Path,
        content_hasher: hashing.StreamingHashEngine,
        *,
        chunk_size: int = 8192,
        digest_name_override: Optional[str] = None,
    ):
        """Initializes an instance to hash a file with a specific `HashEngine`.

        Args:
            file: The file to hash. Use `set_file` to reset it.
            content_hasher: A `hashing.StreamingHashEngine` instance used to
              compute the digest of the file.
            chunk_size: The amount of file to read at once. Default is 8KB. A
              special value of 0 signals to attempt to read everything in a
              single call.
            digest_name_override: Optional string to allow overriding the
              `digest_name` property to support shorter, standardized names.
        """
        if chunk_size < 0:
            raise ValueError(
                f"Chunk size must be non-negative, got {chunk_size}."
            )

        self._file = file
        self._content_hasher = content_hasher
        self._chunk_size = chunk_size
        self._digest_name_override = digest_name_override

    def set_file(self, file: pathlib.Path) -> None:
        """Redefines the file to be hashed in `compute`."""
        self._file = file

    @property
    @override
    def digest_name(self) -> str:
        if self._digest_name_override is not None:
            return self._digest_name_override
        return f"file-{self._content_hasher.digest_name}"

    @override
    def compute(self) -> hashing.Digest:
        self._content_hasher.reset()

        if self._chunk_size == 0:
            with open(self._file, "rb") as f:
                self._content_hasher.update(f.read())
        else:
            with open(self._file, "rb") as f:
                while True:
                    data = f.read(self._chunk_size)
                    if not data:
                        break
                    self._content_hasher.update(data)

        digest = self._content_hasher.compute()
        return hashing.Digest(self.digest_name, digest.digest_value)

    @property
    @override
    def digest_size(self) -> int:
        """The size, in bytes, of the digests produced by the engine."""
        return self._content_hasher.digest_size


class OpenedFileHasher(FileHasher):
    """File hasher using `hashlib.file_digest` to operate on opened files.

    This also supports other file-like objects opened for reading in binary
    mode, e.g., BytesIO, SocketIO.

    Since the `hashlib.file_digest` may bypass Python's I/O, this could be
    faster than `SimpleFileHasher`, at the cost of having the file descriptor
    maintained by the caller, according to `hashlib.file_digest` requirements.
    """

    def __init__(
        self,
        # https://github.com/python/typeshed/issues/2166
        file_descriptor: BinaryIO,
        *,
        algorithm: str = "sha256",
        digest_name_override: Optional[str] = None,
    ):
        """Initializes an instance to hash a file with a specific algorithm.

        Args:
            file_descriptor: Descriptor to the opened file.
            algorithm: a hashing algorithm that can be passed as argument to
              `hashlib.new`. By default, this is "sha256".
            digest_name_override: Optional string to allow overriding the
              `digest_name` property to support shorter, standardized names.
        """
        self._fd = file_descriptor
        self._algorithm = algorithm
        self._digest_name_override = digest_name_override

    def set_file_descriptor(
        self,
        # https://github.com/python/typeshed/issues/2166
        file_descriptor: BinaryIO,
    ) -> None:
        """Redefines the file_descriptor to be hashed in `compute`."""
        self._fd = file_descriptor

    @property
    @override
    def digest_name(self) -> str:
        if self._digest_name_override is not None:
            return self._digest_name_override
        return f"file-fd-{self._algorithm}"

    @override
    def compute(self) -> hashing.Digest:
        if sys.version_info >= (3, 11):
            # https://github.com/python/typeshed/issues/2166
            # pytype: disable=wrong-arg-types
            digest = hashlib.file_digest(self._fd, self._algorithm)
            # pytype: enable=wrong-arg-types
            return hashing.Digest(self.digest_name, digest.digest())

        # Polyfill for Python 3.10
        # https://github.com/python/cpython/blob/4deb32a992/Lib/hashlib.py#L195
        hasher = hashlib.new(self._algorithm)
        buffer = bytearray(2**18)
        view = memoryview(buffer)
        while True:
            size = self._fd.readinto(buffer)
            if size == 0:
                break
            hasher.update(view[:size])
        return hashing.Digest(self.digest_name, hasher.digest())

    @property
    @override
    def digest_size(self) -> int:
        """The size, in bytes, of the digests produced by the engine."""
        return hashlib.new(self._algorithm).digest_size


class ShardedFileHasher(SimpleFileHasher):
    """File hash engine that can be invoked in parallel.

    To efficiently support hashing large files, this class provides an ability
    to compute the digest over a shard of the file. It is the responsibility of
    the user to compose the digests of each shard into a single digest for the
    entire file.
    """

    def __init__(
        self,
        file: pathlib.Path,
        content_hasher: hashing.StreamingHashEngine,
        *,
        start: int,
        end: int,
        chunk_size: int = 8192,
        shard_size: int = 1000000,
        digest_name_override: Optional[str] = None,
    ):
        """Initializes an instance to hash a file with a specific `HashEngine`.

        Args:
            file: The file to hash. Use `set_file` to reset it.
            content_hasher: A `hashing.HashEngine` instance used to compute the
              digest of the file.
            start: The file offset to start reading from. Must be valid. Reset
              with `set_shard`.
            end: The file offset to start reading from. Must be stricly greater
              than start. If past the file size, or -1, it will be trimmed.
              Reset with `set_shard`.
            chunk_size: The amount of file to read at once. Default is 8KB. A
              special value of 0 signals to attempt to read everything in a
              single call.
            shard_size: The size of a file shard. Default is 1,000,000 bytes.
            digest_name_override: Optional string to allow overriding the
              `digest_name` property to support shorter, standardized names.
        """
        super().__init__(
            file=file,
            content_hasher=content_hasher,
            chunk_size=chunk_size,
            digest_name_override=digest_name_override,
        )

        if shard_size <= 0:
            raise ValueError(
                f"Shard size must be strictly positive, got {shard_size}."
            )
        self.shard_size = shard_size

        self.set_shard(start=start, end=end)

    def set_shard(self, *, start: int, end: int) -> None:
        """Redefines the file shard to be hashed in `compute`."""
        if start < 0:
            raise ValueError(
                f"File start offset must be non-negative, got {start}."
            )
        if end <= start:
            raise ValueError(
                "File end offset must be stricly higher that file start offset,"
                f" got {start=}, {end=}."
            )
        read_length = end - start
        if read_length > self.shard_size:
            raise ValueError(
                f"Must not read more than shard_size={self.shard_size}, got"
                f" {read_length}."
            )

        self._start = start
        self._end = end

    @override
    def compute(self) -> hashing.Digest:
        self._content_hasher.reset()

        with open(self._file, "rb") as f:
            f.seek(self._start)
            to_read = self._end - self._start
            if self._chunk_size == 0 or self._chunk_size >= to_read:
                data = f.read(to_read)
                self._content_hasher.update(data)
            else:
                while to_read >= 0:
                    data = f.read(min(self._chunk_size, to_read))
                    if not data:
                        break
                    to_read -= len(data)
                    self._content_hasher.update(data)

        digest = self._content_hasher.compute()
        return hashing.Digest(self.digest_name, digest.digest_value)

    @property
    @override
    def digest_name(self) -> str:
        if self._digest_name_override is not None:
            return self._digest_name_override
        return f"file-{self._content_hasher.digest_name}-{self.shard_size}"
