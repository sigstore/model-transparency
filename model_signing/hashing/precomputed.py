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

"""Precomputed digests.

In order to support digests computed by external tooling, we provide trivial
`HashEngine` instances that just wrap around the digest.

Example usage:
```python
>>> hasher = PrecomputedDigest("short-hash", b"abcd")
>>> hasher.finalize()
>>> hasher.digest_hex
'61626364'
```
"""

from dataclasses import dataclass
from typing_extensions import override

from model_signing.hashing import hashing


@dataclass(frozen=True)
class PrecomputedDigest(hashing.HashEngine):
    """A wrapper around digests computed by external tooling."""

    _digest_type: str
    _digest_value: bytes

    @override
    def update(self, data: bytes) -> None:
        pass  # nothing to do, hash already computed

    @override
    def finalize(self) -> None:
        pass  # nothing to do, hash already computed

    @override
    @property
    def digest_name(self) -> str:
        return self._digest_type

    @override
    @property
    def digest_value(self) -> bytes:
        return self._digest_value

    @override
    @property
    def digest_hex(self) -> str:
        return self._digest_value.hex()
