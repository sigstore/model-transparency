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

"""Precomputed digests.

In order to support digests computed by external tooling, we provide trivial
`HashEngine` instances that just wrap around the digest.

Example usage:
```python
>>> hasher = PrecomputedDigest("short-hash", b"abcd")
>>> digest = hasher.compute()
>>> digest.digest_hex
'61626364'
>>> digest.algorithm
'short-hash'
```
"""

import dataclasses
from typing_extensions import override

from model_signing.hashing import hashing


@dataclasses.dataclass(frozen=True)
class PrecomputedDigest(hashing.HashEngine):
    """A wrapper around digests computed by external tooling."""

    _digest_type: str
    _digest_value: bytes

    @override
    def compute(self) -> hashing.Digest:
        return hashing.Digest(self._digest_type, self._digest_value)

    @property
    @override
    def digest_name(self) -> str:
        return self._digest_type

    @property
    @override
    def digest_size(self) -> int:
        """The size, in bytes, of the digests produced by the engine."""
        return len(self._digest_value)
