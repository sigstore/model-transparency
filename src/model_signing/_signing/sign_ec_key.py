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

import base64
import hashlib

from cryptography import exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.protobuf import json_format
from sigstore_models import intoto as intoto_pb
from sigstore_models.bundle import v1 as bundle_pb
from sigstore_models.common import v1 as common_pb
from typing_extensions import override

from model_signing._signing import sign_sigstore_pb as sigstore_pb
from model_signing._signing import signing


_SUPPORTED_CURVES = [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()]


def _compressed_key_size(curve: ec.EllipticCurve) -> int:
    """Compressed EC public keys: 1 byte prefix + key_size_bytes."""
    return 1 + (curve.key_size + 7) // 8


_COMPRESSED_SIZE_TO_CURVE: dict[int, ec.EllipticCurve] = {
    _compressed_key_size(curve): curve for curve in _SUPPORTED_CURVES
}

_SUPPORTED_CURVE_NAMES: frozenset[str] = frozenset(
    c.name for c in _SUPPORTED_CURVES
)


def _check_supported_curve(curve_name: str):
    """Check if the curve is supported.

    We only support a family of curves, trying to match those specified by
    Sigstore's protobuf specs.
    See https://github.com/sigstore/model-transparency/issues/385.
    """
    if curve_name not in _SUPPORTED_CURVE_NAMES:
        raise ValueError(f"Unsupported curve '{curve_name}'")


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

    match key_size:
        case 256:
            return hashes.SHA256()
        case 384:
            return hashes.SHA384()
        case 521:
            return hashes.SHA512()
        case _:
            raise ValueError(f"Unexpected key size {key_size}")


def _load_private_key(
    private_key: signing.KeyInput, password: str | None = None
) -> ec.EllipticCurvePrivateKey:
    """Load a private key from a path or bytes.

    Args:
        private_key: Either a path to a PEM-encoded private key file, or bytes
            containing the PEM-encoded private key.
        password: Optional password for the private key.

    Returns:
        The loaded private key.

    Raises:
        ValueError: If the key format is invalid or unsupported.
    """
    key_bytes = signing.read_bytes_input(private_key)
    loaded_key = serialization.load_pem_private_key(key_bytes, password)
    if not isinstance(loaded_key, ec.EllipticCurvePrivateKey):
        raise ValueError("Only elliptic curve private keys are supported")
    _check_supported_curve(loaded_key.curve.name)
    return loaded_key


def _load_public_key(public_key: signing.KeyInput) -> ec.EllipticCurvePublicKey:
    """Load a public key from a path, bytes (PEM/DER), or compressed format.

    Args:
        public_key:
            - A path to a PEM or DER-encoded public key file
            - Bytes containing PEM or DER-encoded public key
            - Compressed public key bytes (33 for secp256r1, 49 for secp384r1,
              67 for secp521r1)

    Returns:
        The loaded public key.

    Raises:
        ValueError: If the key format is invalid or unsupported.
        TypeError: If the input type is not supported.
    """
    key_bytes = signing.read_bytes_input(public_key)

    curve = _COMPRESSED_SIZE_TO_CURVE.get(len(key_bytes))
    if curve is not None:
        try:
            return ec.EllipticCurvePublicKey.from_encoded_point(
                curve, key_bytes
            )
        except (ValueError, exceptions.UnsupportedAlgorithm) as e:
            raise ValueError(
                f"Failed to load compressed public key for {curve.name}: {e}"
            ) from e

    try:
        loaded_key = serialization.load_pem_public_key(key_bytes)
    except ValueError:
        try:
            loaded_key = serialization.load_der_public_key(key_bytes)
        except ValueError as e:
            raise ValueError(
                "Failed to load public key. Expected PEM, DER, or compressed "
                "EC point format."
            ) from e

    if not isinstance(loaded_key, ec.EllipticCurvePublicKey):
        raise ValueError("Only elliptic curve public keys are supported")
    _check_supported_curve(loaded_key.curve.name)
    return loaded_key


class Signer(sigstore_pb.Signer):
    """Signer using an elliptic curve private key."""

    def __init__(
        self, private_key: signing.KeyInput, password: str | None = None
    ):
        """Initializes the signer with the private key and optional password.

        Args:
            private_key: Either a path to a PEM-encoded private key file,
                or bytes containing the PEM-encoded private key.
            password: Optional password for the private key.
        """
        self._private_key = _load_private_key(private_key, password)

    @override
    def sign(self, payload: signing.Payload) -> signing.Signature:
        raw_payload = json_format.MessageToJson(payload.statement.pb).encode(
            "utf-8"
        )

        raw_signature = intoto_pb.Signature(
            sig=base64.b64encode(
                self._private_key.sign(
                    sigstore_pb.pae(raw_payload),
                    ec.ECDSA(get_ec_key_hash(self._private_key.public_key())),
                )
            ),
            keyid="",
        )

        envelope = intoto_pb.Envelope(
            payload=base64.b64encode(raw_payload),
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

        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        hash_bytes = hashlib.sha256(raw_bytes).digest().hex()

        return bundle_pb.VerificationMaterial(
            public_key=common_pb.PublicKeyIdentifier(hint=hash_bytes),
            tlog_entries=[],
        )


class Verifier(sigstore_pb.Verifier):
    """Verifier for signatures generated with an elliptic curve private key."""

    def __init__(self, public_key: signing.KeyInput):
        """Initializes the verifier with the public key to use.

        Args:
            public_key:
                - A path to a PEM or DER-encoded public key file
                - Bytes containing PEM or DER-encoded public key
                - Compressed public key bytes (33 for secp256r1, 49 for
                  secp384r1, 67 for secp521r1)
                This must be paired with the private key used to generate
                the signature.
        """
        self._public_key = _load_public_key(public_key)

    @override
    def _verify_bundle(self, bundle: bundle_pb.Bundle) -> tuple[str, bytes]:
        raw_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        hash_bytes = hashlib.sha256(raw_bytes).digest().hex()

        if bundle.verification_material.public_key.hint:
            key_hint = bundle.verification_material.public_key.hint
            if key_hint != hash_bytes:
                raise ValueError(
                    "Key mismatch: The public key hash in the signature's "
                    "verification material does not match the provided "
                    "public key. "
                )
        else:
            print(
                "WARNING: This model's signature uses an older "
                "verification material format. Please re-sign "
                "with an updated signer to use a public key "
                "identifier hash. "
            )

        envelope = bundle.dsse_envelope
        try:
            self._public_key.verify(
                envelope.signatures[0].sig,
                sigstore_pb.pae(envelope.payload),
                ec.ECDSA(get_ec_key_hash(self._public_key)),
            )
        except exceptions.InvalidSignature:
            # Compatibility layer with pre 1.0 release
            # Here, we patch over a bug in `pae` which mixed unicode `str` and
            # `bytes`. As a result, additional escape characters were added to
            # the material that got signed over.
            self._public_key.verify(
                envelope.signatures[0].sig,
                sigstore_pb.pae_compat(envelope.payload),
                ec.ECDSA(get_ec_key_hash(self._public_key)),
            )

        return envelope.payload_type, envelope.payload
