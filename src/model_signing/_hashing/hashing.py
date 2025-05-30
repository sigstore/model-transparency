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

"""Machinery for computing digests for a single object.

The `Digest` object represents the algorithm used to summarize (hash) an object
(file, chunk of file, etc.) and the value of the digest. These are the values
that are stored in signature files.

To support multiple hashing formats, we define an abstract `HashEngine` class
which can be used in type annotations and is at the root of the hashing classes
hierarchy.

To support updating the hash of an object when more data is being added, we also
define a `Streaming` protocol which we then use to define an abstract
`StreamingHashEngine`.

These two types of hashing engines are used to hash any of the objects that we
can generate a signature over.
"""

import abc
import dataclasses
from typing import Protocol


@dataclasses.dataclass(frozen=True)
class Digest:
    """A digest computed by a `HashEngine`.

    Attributes:
        algorithm: The algorithm used to compute the digest. This could be a
          canonical name (e.g. "sha256" for SHA256) or a name that uniquely
          encodes the algorithm being used for the purposes of this library
          (e.g., "sha256-sharded-1024" for a digest produced by computing SHA256
          hashes of shards of 1024 bytes of the object).  This name can be used
          to autodetect the hashing configuration used during signing so that
          verification can compute a similar digest.
        digest_value: The value of the digest.
    """

    algorithm: str
    digest_value: bytes

    @property
    def digest_hex(self) -> str:
        """Hexadecimal, human readable, equivalent of `digest`."""
        return self.digest_value.hex()

    @property
    def digest_size(self) -> int:
        """The size, in bytes, of the digest."""
        return len(self.digest_value)


class HashEngine(metaclass=abc.ABCMeta):
    """Generic hash engine."""

    @abc.abstractmethod
    def compute(self) -> Digest:
        """Computes the digest of data passed to the engine."""

    @property
    @abc.abstractmethod
    def digest_name(self) -> str:
        """The canonical name of the algorithm used to compute the hash.

        Subclasses MUST use the `digest_name()` method to record all parameters
        that influence the hash output. For example, if a file is split into
        shards which are hashed separately and the final digest value is
        computed by aggregating these hashes, then the shard size must be given
        in the output string.

        This name gets transferred to the `algorithm` field of the `Digest`
        computed by the hashing engine.
        """

    @property
    @abc.abstractmethod
    def digest_size(self) -> int:
        """The size, in bytes, of the digests produced by the engine.

        This must return the same value as calling `digest_size` on the `Digest`
        object produced by the hashing engine.
        """


class Streaming(Protocol):
    """A protocol to support streaming data to `HashEngine` objects."""

    @abc.abstractmethod
    def update(self, data: bytes) -> None:
        """Appends additional bytes to the data to be hashed.

        Args:
            data: The new data that should be hashed.
        """

    @abc.abstractmethod
    def reset(self, data: bytes = b"") -> None:
        """Resets the data to be hashed to the passed argument.

        Args:
            data: Optional, initial data to hash.
        """


class StreamingHashEngine(Streaming, HashEngine):
    """A `HashEngine` that can stream data to be hashed."""
