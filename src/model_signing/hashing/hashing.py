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

We define an abstract `HashEngine` class which can be used in type annotations
and is at the root of the hashing classes hierarchy.

Since there are multiple hashing methods that we support, users should always
specify the algorithm and the digest value.
"""

import abc
import dataclasses
from typing import Protocol


@dataclasses.dataclass(frozen=True)
class Digest:
    """A digest computed by a `HashEngine`."""

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
        pass

    @property
    @abc.abstractmethod
    def digest_name(self) -> str:
        """The canonical name of the algorithm used to compute the hash.

        Subclasses MUST use the `digest_name()` method to record all parameters
        that influence the hash output. For example, if a file is split into
        shards which are hashed separately and the final digest value is
        computed by aggregating these hashes, then the shard size must be given
        in the output string.
        """
        pass

    @property
    @abc.abstractmethod
    def digest_size(self) -> int:
        """The size, in bytes, of the digests produced by the engine."""
        pass


class Streaming(Protocol):
    """A protocol to support streaming data to `HashEngine` objects."""

    @abc.abstractmethod
    def update(self, data: bytes) -> None:
        """Appends additional bytes to the data to be hashed."""
        pass

    @abc.abstractmethod
    def reset(self, data: bytes = b"") -> None:
        """Resets the data to be hashed to the passed argument."""
        pass


class StreamingHashEngine(Streaming, HashEngine):
    """A `HashEngine` that can stream data to be hashed."""

    pass
