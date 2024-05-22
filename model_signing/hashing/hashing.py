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
# See the License for the specific language governing perepo_managerissions and
# limitations under the License.

"""Machinery for computing digests for a single object.

We define an abstract `HashEngine` class which can be used in type annotations
and is at the root of the hashing classes hierarchy.

Since there are multiple hashing methods that we support, users should always
specify the algorithm and the digest value.
"""

from abc import ABCMeta, abstractmethod


class HashEngine(metaclass=ABCMeta):
    """Generic hash engine."""

    @abstractmethod
    def update(self, data: bytes) -> None:
        """Updates the digest based on new bytes.

        Repeated calls are equivalent to a single call with the concatenation of
        all the arguments. That is, `he.update(a); he.update(b)` is the same as
        `he.update(a + b)`.

        If `finalize` has been called, the behavior of subsequent calls to
        `update` is implementation specific.
        """
        pass

    @abstractmethod
    def finalize(self) -> None:
        """Records that the entire object has been passed to the engine.

        This method MUST be called only once, after which only the computed
        digest and the name of the algorithm can be accessed. This is to ensure
        that hashing methods that rely on FFI or use aditional resources (e.g.,
        compute the digest on GPU) can properly free allocated resources.

        Calling `finalize` more than once may not result in an error. Instead,
        in order to allow for implementations that don't need to perform
        additional testing, the behavior is implementation specific.
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

    @property
    @abstractmethod
    def digest_value(self) -> bytes:
        """The digest of the data passed to the hash engine.

        The returned value is only valid if `finalize` has been previously
        called. For all other cases, the returned value is implementation
        specific.
        """
        pass

    @property
    @abstractmethod
    def digest_hex(self) -> str:
        """Hexadecimal, human readable, equivalent of `digest_value`.

        In general, this method should be used only in tests and for debugging.

        The returned value is only valid if `finalize` has been previously
        called. For all other cases, the returned value is implementation
        specific.
        """
        pass
