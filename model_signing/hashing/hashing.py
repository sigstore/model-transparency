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

from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from typing import Protocol
from typing_extensions import override


@dataclass(frozen = True)
class Digest:
    """A digest computed by a `HashEngine`."""
    algorithm: str
    digest_value: bytes

    @property
    def digest_hex(self) -> str:
        """Hexadecimal, human readable, equivalent of `digest`."""
        return self.digest_value.hex()


class HashEngine(metaclass=ABCMeta):
    """Generic hash engine."""

    @abstractmethod
    def compute(self) -> Digest:
        """Computes the digest of data passed to the engine.

        Subclasses should add additional arguments to `compute()` method to pass
        in the data that needs to be hashed. Alternatively, if the data can be
        passed in iteratively, users should use `StreamingHashEngine` instead.
        """
        pass

    @property
    @abstractmethod
    def digest_name(self) -> str:
        """The canonical name of the algorithm used to compute the hash.

        Subclasses MUST use the `digest_name()` method to record all parameters
        that influence the hash output. For example, if a file is split into
        shards which are hashed separately and the final digest value is
        computed by aggregating these hashes, then the shard size must be given
        in the output string.

        This method may be called at any time during the lifetime of a
        `HashEngine` instance.
        """
        pass


class Streaming(Protocol):
    """A protocol to support streaming data to `HashEngine` objects."""
    current_digest: Digest

    @abstractmethod
    def update(self, data: bytes) -> None:
        """Appends additional bytes to the data to be hashed.

        Implementations might decide to not support this operation.

        Similarly, implementations might decide to not support this operation
        after `compute` has been called. Or, they might decide that additional
        calls to `update` after `compute` has been called have no effect.

        Implementations may update internal data on each call to `update`
        instead of performing the entire digest computation on `compute`.
        """
        pass

    @abstractmethod
    def reset(self) -> None:
        """Resets the data to be hashed to be empty."""
        pass


class StreamingHashEngine(Streaming, HashEngine):
    """A `HashEngine` that can stream data to be hashed."""

    @override
    def compute(self) -> Digest:
        return self.current_digest
