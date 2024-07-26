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
"""This package provides the functionality to sign and verify models
with keys."""
from typing import Optional
from typing_extensions import override

import dataclasses

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.hashes import SHA256
from google.protobuf import json_format
from in_toto_attestation.v1 import statement
from in_toto_attestation.v1 import statement_pb2 as statement_pb
from sigstore_protobuf_specs.dev.sigstore.bundle import v1 as bundle_pb
from sigstore_protobuf_specs.dev.sigstore.common import v1 as common_pb
from sigstore_protobuf_specs.io import intoto as intoto_pb

from model_signing.signature import encoding
from model_signing.signature import signature


def load_ec_private_key(
        path: str, password: Optional[str] = None
        ) -> ec.EllipticCurvePrivateKey:
    private_key: ec.EllipticCurvePrivateKey
    with open(path, "rb") as fd:
        serialized_key = fd.read()
    private_key = serialization.load_pem_private_key(
        serialized_key, password=password
    )
    return private_key


@dataclasses.dataclass(frozen=True)
class ECVerificationMaterial(signature.SigstoreVerificationMaterial):
    key: ec.EllipticCurvePublicKey
    signature_algorithm: ec.EllipticCurveSignatureAlgorithm

    @override
    def to_sigstore_verification_material(
            self) -> bundle_pb.VerificationMaterial:
        key_size = self.key.key_size
        if isinstance(self.signature_algorithm.algorithm, utils.PreHashed):
            raise TypeError(
                "PreHashed is not supported by the sigstore bundle")
        hash_alg = self.signature_algorithm.algorithm.name
        key_details = common_pb.PublicKeyDetails.from_string(
            f"PKIX_ECDSA_P{key_size}_{hash_alg}"
        )
        return bundle_pb.VerificationMaterial(
            public_key=common_pb.PublicKey(
                raw_bytes=self.key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
                key_details=key_details,
            )
        )


class ECKeySigner(signature.BytesSigner):
    """Provides a Signer using an elliptic curve private key for signing."""

    def __init__(
            self,
            private_key: ec.EllipticCurvePrivateKey,
            signature_algorithm:
            ec.EllipticCurveSignatureAlgorithm | None = None
            ):
        self._private_key = private_key
        self._signature_alg = signature_algorithm if signature_algorithm else \
            ec.ECDS(SHA256())

    @classmethod
    def from_path(cls, private_key_path: str, password: Optional[str] = None):
        private_key = load_ec_private_key(private_key_path, password)
        return cls(private_key)

    @override
    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data, self._signature_alg)

    @property
    @override
    def verification_material(self) -> ECVerificationMaterial:
        return ECVerificationMaterial(
            key=self._private_key.public_key,
            signature_algorithm=self._signature_alg)


class ECKeyVerifier(signature.BytesVerifier):
    """Provides a verifier using a public key."""

    def __init__(self, material: ECVerificationMaterial):
        self._verification_material = material

    @classmethod
    def from_path(cls, key_path: str):
        with open(key_path, 'rb') as fd:
            serialized_key = fd.read()
        public_key = serialization.load_pem_public_key(serialized_key)
        return cls(ECVerificationMaterial(public_key))

    @override
    def verify(self, signature: bytes, data: bytes):
        try:
            self._verification_material.key.verify(
                signature,
                data,
                self._verification_material.signature_algorithm)
        except Exception as e:
            raise ValueError("signature verification failed" + str(e)) from e
