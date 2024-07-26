# Copyright (c) 2024, NVIDIA CORPORATION.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from pathlib import Path
from typing import Self
from typing_extensions import override

import dataclasses
import json

from model_signing.hashing import hashing
from model_signing.manifest.manifest import ResourceDescriptor
from model_signing.manifest.manifest import Manifest
from model_signing.signature import signature
from model_signing.signing import signing


class ManifestPayload(signing.SigningPayload):

    def __init__(
            self, resource_descriptors: list[ResourceDescriptor]):
        self._items: dict[str, hashing.Digest] = {
            r.identifier: r.digest for r in resource_descriptors
        }

    @classmethod
    @override
    def from_manifest(cls, manifest: Manifest) -> Self:
        descriptors = []
        for d in manifest.resource_descriptors:
            descriptors.append(d)
        return cls(descriptors)

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, type(self)):
            raise TypeError(f"cannot compare {type(value)} with {type(self)}")
        return self._items == value._items


@dataclasses.dataclass(frozen=True)
class ManifestSignature(signing.Signature):
    signature_data: bytes
    payload_data: bytes
    verification_material: signature.SigstoreVerificationMaterial

    @override
    def write(self, path: Path) -> None:
        return super().write(path)

    @classmethod
    @override
    def read(cls, path: Path) -> Self:
        return super().read(path)


class ManifestSigner(signing.Signer):

    def __init__(self, bytes_signer: signature.BytesSigner) -> None:
        self._signer = bytes_signer

    @override
    def sign(self, payload: ManifestPayload) -> ManifestSignature:
        payload_data = json.dumps(payload._items).encode()
        sig = self._signer.sign(payload_data)
        return ManifestSignature(
            sig, payload_data, self._signer.verification_material)


class ManifestVerifier(signing.Verifier):

    def __init__(self) -> None:
        super().__init__()