# Copyright 2025 The Sigstore Authors
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

"""Signers and verifiers using elliptic curve keys."""

import pathlib
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.protobuf import json_format
from sigstore_protobuf_specs.dev.sigstore.bundle import v1 as bundle_pb
from sigstore_protobuf_specs.dev.sigstore.common import v1 as common_pb
from sigstore_protobuf_specs.io import intoto as intoto_pb
from typing_extensions import override

from model_signing._signing import sign_sigstore_pb as sigstore_pb
from model_signing._signing import signing


def _check_supported_ec_key(public_key: ec.EllipticCurvePublicKey):
    """Checks if the elliptic curve key is supported by our package.

    We only support a family of curves, trying to match those specified by
    Sigstore's protobuf specs.
    See https://github.com/sigstore/model-transparency/issues/385.

    Args:
        public_key: The public key to check. Can be obtained from a private key.

    Raises:
        ValueError: The key is not supported.
    """
    curve = public_key.curve.name
    if curve not in ["secp256r1", "secp384r1", "secp521r1"]:
        raise ValueError(f"Unsupported key for curve '{curve}'")


def get_ec_key_hash(
    public_key: ec.EllipticCurvePublicKey,
) -> hashes.HashAlgorithm:
    """Returns the public key hashing algorithm.

    We need to record this in the sigstore bundle when signing and retrieve when
    performing verification. This is according to sigstore protobuf specs and is
    used both when signing with keys and when signing with certificates.

    Args:
        public_key: The public key to get the hash algorithm from.

    Raises:
        ValueError: The key is not supported.
    """
    key_size = public_key.curve.key_size

    # TODO: Once Python 3.9 support is deprecated revert to using `match`
    if key_size == 256:
        return hashes.SHA256()
    if key_size == 384:
        return hashes.SHA384()
    if key_size == 521:
        return hashes.SHA512()

    raise ValueError(f"Unexpected key size {key_size}")


class Signer(sigstore_pb.Signer):
    """Signer using an elliptic curve private key."""

    def __init__(
        self, private_key_path: pathlib.Path, password: Optional[str] = None
    ):
        """Initializes the signer with the private key and optional password.

        Args:
            private_key_path: The path to the PEM encoded private key.
            password: Optional password for the private key.
        """
        self._private_key = serialization.load_pem_private_key(
            private_key_path.read_bytes(), password
        )
        _check_supported_ec_key(self._private_key.public_key())

    @override
    def sign(self, payload: signing.Payload) -> signing.Signature:
        raw_payload = json_format.MessageToJson(payload.statement.pb).encode(
            "utf-8"
        )

        raw_signature = intoto_pb.Signature(
            sig=self._private_key.sign(
                sigstore_pb.pae(raw_payload),
                ec.ECDSA(get_ec_key_hash(self._private_key.public_key())),
            ),
            keyid=None,
        )

        envelope = intoto_pb.Envelope(
            payload=raw_payload,
            payload_type=signing._IN_TOTO_JSON_PAYLOAD_TYPE,
            signatures=[raw_signature],
        )

        return sigstore_pb.Signature(
            bundle_pb.Bundle(
                media_type=sigstore_pb._BUNDLE_MEDIA_TYPE,
                verification_material=self._get_verification_material(),
                dsse_envelope=envelope,
            )
        )

    def _get_verification_material(self) -> bundle_pb.VerificationMaterial:
        """Returns the verification material to include in the bundle."""
        public_key = self._private_key.public_key()
        key_size = public_key.curve.key_size

        # TODO: Once Python 3.9 support is deprecated revert to using `match`
        if key_size == 256:
            key_details = common_pb.PublicKeyDetails.PKIX_ECDSA_P256_SHA_256
        elif key_size == 384:
            key_details = common_pb.PublicKeyDetails.PKIX_ECDSA_P384_SHA_384
        elif key_size == 521:
            key_details = common_pb.PublicKeyDetails.PKIX_ECDSA_P521_SHA_512
        else:
            raise ValueError(f"Unexpected key size {key_size}")

        return bundle_pb.VerificationMaterial(
            public_key=common_pb.PublicKey(
                raw_bytes=public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
                key_details=key_details,
            )
        )


class Verifier(sigstore_pb.Verifier):
    """Verifier for signatures generated with an elliptic curve private key."""

    def __init__(self, public_key_path: pathlib.Path):
        """Initializes the verifier with the public key to use.

        Args:
            public_key_path: The path to the public key to use. This must be
              paired with the private key used to generate the signature.
        """
        self._public_key = serialization.load_pem_public_key(
            public_key_path.read_bytes()
        )
        _check_supported_ec_key(self._public_key)

    @override
    def _verify_bundle(self, bundle: bundle_pb.Bundle) -> tuple[str, bytes]:
        # TODO: This method currently does not verify that the public key
        # matches what is included in the signature's verification material.
        # Instead, the verification material is completely ignored right now.

        envelope = bundle.dsse_envelope
        self._public_key.verify(
            envelope.signatures[0].sig,
            sigstore_pb.pae(envelope.payload),
            ec.ECDSA(get_ec_key_hash(self._public_key)),
        )

        return envelope.payload_type, envelope.payload
