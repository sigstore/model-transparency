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

import base64
import hashlib
from urllib.parse import parse_qs
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.protobuf import json_format
from sigstore_models import intoto as intoto_pb
from sigstore_models.bundle import v1 as bundle_pb
from sigstore_models.common import v1 as common_pb
from typing_extensions import override

from model_signing._signing import sign_ec_key as ec_key
from model_signing._signing import sign_sigstore_pb as sigstore_pb
from model_signing._signing import signing
from model_signing._signing.sign_ec_key import _check_supported_ec_key


class AWSKMSBackend:
    """AWS KMS backend for signing with keys stored in AWS KMS."""

    def __init__(self, key_id: str, region: str | None = None):
        """Initializes the AWS KMS backend.

        Args:
            key_id: The AWS KMS key ID or ARN.
            region: Optional AWS region. If not provided, uses default region.
        """
        try:
            import boto3
        except ImportError as e:
            raise RuntimeError(
                "AWS KMS support requires 'boto3'. "
                "Install with 'pip install boto3'."
            ) from e

        self._key_id = key_id
        self._kms_client = boto3.client("kms", region_name=region)
        self._public_key = self._get_public_key()

    def _get_public_key(self) -> ec.EllipticCurvePublicKey:
        response = self._kms_client.get_public_key(KeyId=self._key_id)
        public_key_der = response["PublicKey"]
        public_key = serialization.load_der_public_key(public_key_der)
        _check_supported_ec_key(public_key)
        return public_key

    def sign(self, digest: bytes) -> bytes:
        response = self._kms_client.sign(
            KeyId=self._key_id,
            Message=digest,
            MessageType="DIGEST",
            SigningAlgorithm=(
                "ECDSA_SHA_256"
                if self._public_key.curve.name == "secp256r1"
                else "ECDSA_SHA_384"
                if self._public_key.curve.name == "secp384r1"
                else "ECDSA_SHA_512"
            ),
        )
        sig_bytes = response["Signature"]
        return sig_bytes

    def get_public_key(self) -> ec.EllipticCurvePublicKey:
        return self._public_key


def _parse_kms_uri(kms_uri: str) -> tuple[str, dict[str, str]]:
    """Parses a KMS URI into provider and parameters.

    Supported formats:
    - kms://aws/<key-id-or-arn>?region=<region>

    For additional KMS providers (GCP, Azure, etc.), please open an issue at:
    https://github.com/sigstore/model-transparency/issues

    Args:
        kms_uri: The KMS URI to parse.

    Returns:
        A tuple of (provider, parameters dict).
    """
    parsed = urlparse(kms_uri)
    if parsed.scheme != "kms":
        raise ValueError(f"Invalid KMS URI scheme: {parsed.scheme}")

    provider = parsed.netloc
    path_parts = [p for p in parsed.path.split("/") if p]
    query_params = parse_qs(parsed.query)

    params = {}
    if provider == "aws":
        if len(path_parts) == 0:
            raise ValueError(
                "AWS KMS URI must have format: kms://aws/<key-id-or-arn>"
            )
        key_id = "/".join(path_parts)
        if key_id.startswith("arn:aws:kms:"):
            arn_parts = key_id.split(":")
            if len(arn_parts) != 6 or arn_parts[5].split("/")[0] != "key":
                raise ValueError(
                    "AWS KMS ARN must have format: "
                    "arn:aws:kms:<region>:<account-id>:key/<key-id>"
                )
        elif "/" in key_id:
            raise ValueError(
                "AWS KMS URI must be either a full ARN "
                "(arn:aws:kms:...) or a simple key ID"
            )
        params["key_id"] = key_id
        if "region" in query_params:
            params["region"] = query_params["region"][0]
    else:
        raise ValueError(
            f"Unsupported KMS provider: {provider}. "
            "Currently only AWS KMS is supported. "
            "For other providers, please open an issue at: "
            "https://github.com/sigstore/model-transparency/issues"
        )

    return provider, params


class Signer(sigstore_pb.Signer):
    """Signer using KMS URIs with elliptic curve keys."""

    def __init__(self, kms_uri: str):
        """Initializes the KMS signer.

        Args:
            kms_uri: The KMS URI specifying the provider and key.
        """
        provider, params = _parse_kms_uri(kms_uri)

        if provider == "aws":
            self._backend = AWSKMSBackend(
                params["key_id"], params.get("region")
            )
        else:
            raise ValueError(f"Unsupported KMS provider: {provider}")

        self._public_key = self._backend.get_public_key()

    def public_key(self):
        """Get the python cryptography public key."""
        return self._public_key

    @override
    def sign(self, payload: signing.Payload) -> signing.Signature:
        raw_payload = json_format.MessageToJson(payload.statement.pb).encode(
            "utf-8"
        )

        hash_alg = ec_key.get_ec_key_hash(self._public_key)
        pae_payload = sigstore_pb.pae(raw_payload)

        hash_obj = hashes.Hash(hash_alg)
        hash_obj.update(pae_payload)
        digest = hash_obj.finalize()

        sig = self._backend.sign(digest)

        raw_signature = intoto_pb.Signature(sig=base64.b64encode(sig), keyid="")

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
        public_key = self._public_key

        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        hash_bytes = hashlib.sha256(raw_bytes).digest().hex()

        return bundle_pb.VerificationMaterial(
            public_key=common_pb.PublicKeyIdentifier(hint=hash_bytes),
            tlog_entries=[],
        )
