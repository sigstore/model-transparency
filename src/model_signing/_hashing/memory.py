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

"""Digests for memory objects.

These can only compute hashes of objects residing in memory, after they get
converted to bytes.

Example usage:
```python
>>> hasher = SHA256()
>>> hasher.update(b"abcd")
>>> digest = hasher.compute()
>>> digest.digest_hex
'88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589'
```

Or, passing the data directly in the constructor:
```python
>>> hasher = SHA256(b"abcd")
>>> digest = hasher.compute()
>>> digest.digest_hex
'88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589'
```
"""

import hashlib

from typing_extensions import override

from model_signing._hashing import hashing


class SHA256(hashing.StreamingHashEngine):
    """A wrapper around `hashlib.sha256`."""

    def __init__(self, initial_data: bytes = b""):
        """Initializes an instance of a SHA256 hash engine.

        Args:
            initial_data: Optional initial data to hash.
        """
        self._hasher = hashlib.sha256(initial_data)

    @override
    def update(self, data: bytes) -> None:
        self._hasher.update(data)

    @override
    def reset(self, data: bytes = b"") -> None:
        self._hasher = hashlib.sha256(data)

    @override
    def compute(self) -> hashing.Digest:
        return hashing.Digest(self.digest_name, self._hasher.digest())

    @property
    @override
    def digest_name(self) -> str:
        return "sha256"

    @property
    @override
    def digest_size(self) -> int:
        return self._hasher.digest_size


class BLAKE2(hashing.StreamingHashEngine):
    """A wrapper around `hashlib.blake2b`."""

    def __init__(self, initial_data: bytes = b""):
        """Initializes an instance of a BLAKE2 hash engine.

        Args:
            initial_data: Optional initial data to hash.
        """
        self._hasher = hashlib.blake2b(initial_data)

    @override
    def update(self, data: bytes) -> None:
        self._hasher.update(data)

    @override
    def reset(self, data: bytes = b"") -> None:
        self._hasher = hashlib.blake2b(data)

    @override
    def compute(self) -> hashing.Digest:
        return hashing.Digest(self.digest_name, self._hasher.digest())

    @property
    @override
    def digest_name(self) -> str:
        return "blake2b"

    @property
    @override
    def digest_size(self) -> int:
        return self._hasher.digest_size
