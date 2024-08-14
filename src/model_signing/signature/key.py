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
"""Functionality to sign and verify models with keys."""

from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from google.protobuf import json_format
from in_toto_attestation.v1 import statement
from in_toto_attestation.v1 import statement_pb2 as statement_pb
from sigstore_protobuf_specs.dev.sigstore.bundle import v1 as bundle_pb
from sigstore_protobuf_specs.dev.sigstore.common import v1 as common_pb
from sigstore_protobuf_specs.io import intoto as intoto_pb

from model_signing.signature import encoding
from model_signing.signature.signing import Signer
from model_signing.signature.verifying import VerificationError
from model_signing.signature.verifying import Verifier


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


class ECKeySigner(Signer):
    """Provides a Signer using an elliptic curve private key for signing."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey):
        self._private_key = private_key

    @classmethod
    def from_path(cls, private_key_path: str, password: Optional[str] = None):
        private_key = load_ec_private_key(private_key_path, password)
        return cls(private_key)

    def sign(self, stmnt: statement.Statement) -> bundle_pb.Bundle:
        pae = encoding.pae(stmnt.pb)
        sig = self._private_key.sign(pae, ec.ECDSA(SHA256()))
        env = intoto_pb.Envelope(
            payload=json_format.MessageToJson(stmnt.pb).encode(),
            payload_type=encoding.PAYLOAD_TYPE,
            signatures=[intoto_pb.Signature(sig=sig, keyid=None)],
        )
        bdl = bundle_pb.Bundle(
            media_type="application/vnd.dev.sigstore.bundle.v0.3+json",
            verification_material=bundle_pb.VerificationMaterial(
                public_key=common_pb.PublicKey(
                    raw_bytes=self._private_key.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    ),
                    key_details=common_pb.PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
                )
            ),
            dsse_envelope=env,
        )

        return bdl


class ECKeyVerifier(Verifier):
    """Provides a verifier using a public key."""

    def __init__(self, public_key: ec.EllipticCurvePublicKey):
        self._public_key = public_key

    @classmethod
    def from_path(cls, key_path: str):
        with open(key_path, "rb") as fd:
            serialized_key = fd.read()
        public_key = serialization.load_pem_public_key(serialized_key)
        return cls(public_key)

    def verify(self, bundle: bundle_pb.Bundle) -> None:
        statement = json_format.Parse(
            bundle.dsse_envelope.payload,
            statement_pb.Statement(),  # pylint: disable=no-member
        )
        pae = encoding.pae(statement)
        try:
            self._public_key.verify(
                bundle.dsse_envelope.signatures[0].sig, pae, ec.ECDSA(SHA256())
            )
        except Exception as e:
            raise VerificationError(
                "signature verification failed " + str(e)
            ) from e
