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
import pathlib
from urllib.parse import parse_qs
from urllib.parse import urlparse

from asn1crypto.algos import DSASignature
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


class KMSBackend:
    """Base class for KMS backends."""

    def sign(self, data: bytes, is_digest: bool = False) -> bytes:
        """Signs data using the KMS.

        Args:
            data: The data to sign (either raw data or digest).
            is_digest: If True, data is already a digest. If False, data
                should be signed directly (for backends that handle hashing).

        Returns:
            The signature in ASN.1 DER format.
        """
        raise NotImplementedError

    def get_public_key(self) -> ec.EllipticCurvePublicKey:
        """Gets the public key from the KMS.

        Returns:
            The public key.
        """
        raise NotImplementedError


class FileKMSBackend(KMSBackend):
    """File-based KMS backend for testing."""

    def __init__(self, key_path: pathlib.Path):
        """Initializes the file-based KMS backend.

        Args:
            key_path: Path to a PEM-encoded private key file.
        """
        self._private_key = serialization.load_pem_private_key(
            key_path.read_bytes(), None
        )
        if not isinstance(self._private_key, ec.EllipticCurvePrivateKey):
            raise ValueError("Only elliptic curve keys are supported")
        _check_supported_ec_key(self._private_key.public_key())

    def sign(self, data: bytes, is_digest: bool = False) -> bytes:
        hash_alg = ec_key.get_ec_key_hash(self._private_key.public_key())
        sig_bytes = self._private_key.sign(data, ec.ECDSA(hash_alg))
        return sig_bytes

    def get_public_key(self) -> ec.EllipticCurvePublicKey:
        return self._private_key.public_key()


class AWSKMSBackend(KMSBackend):
    """AWS KMS backend."""

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

    def sign(self, data: bytes, is_digest: bool = False) -> bytes:
        if not is_digest:
            raise ValueError("AWS KMS requires pre-hashed digest")
        response = self._kms_client.sign(
            KeyId=self._key_id,
            Message=data,
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


class GCPKMSBackend(KMSBackend):
    """Google Cloud KMS backend."""

    def __init__(
        self, project_id: str, location: str, keyring: str, key_name: str
    ):
        """Initializes the GCP KMS backend.

        Args:
            project_id: The GCP project ID.
            location: The GCP location (e.g., 'us-east1').
            keyring: The keyring name.
            key_name: The key name.
        """
        try:
            from google.cloud import kms
        except ImportError as e:
            raise RuntimeError(
                "GCP KMS support requires 'google-cloud-kms'. "
                "Install with 'pip install google-cloud-kms'."
            ) from e

        self._kms = kms
        self._key_path = (
            f"projects/{project_id}/locations/{location}/"
            f"keyRings/{keyring}/cryptoKeys/{key_name}"
        )
        self._kms_client = kms.KeyManagementServiceClient()
        self._public_key = self._get_public_key()

    def _get_public_key(self) -> ec.EllipticCurvePublicKey:
        key = self._kms_client.get_crypto_key(name=self._key_path)
        if key.purpose != self._kms.CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN:
            raise ValueError("Key must be for asymmetric signing")
        algo = key.version_template.algorithm
        algo_p256 = (
            self._kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256  # noqa: E501
        )
        algo_p384 = (
            self._kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P384_SHA384  # noqa: E501
        )
        algo_p521 = (
            self._kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P521_SHA512  # noqa: E501
        )
        if algo != algo_p256 and algo != algo_p384 and algo != algo_p521:
            raise ValueError("Only ECDSA keys are supported")

        crypto_key_version = self._kms_client.get_crypto_key_version(
            name=f"{self._key_path}/cryptoKeyVersions/1"
        )
        public_key_der = crypto_key_version.public_key.key_data
        public_key = serialization.load_der_public_key(public_key_der)
        _check_supported_ec_key(public_key)
        return public_key

    def sign(self, data: bytes, is_digest: bool = False) -> bytes:
        if not is_digest:
            raise ValueError("GCP KMS requires pre-hashed digest")
        hash_alg = ec_key.get_ec_key_hash(self._public_key)
        if hash_alg.name == "sha256":
            algorithm = (
                self._kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256  # noqa: E501
            )
            digest_obj = self._kms.Digest(sha256=data)
        elif hash_alg.name == "sha384":
            algorithm = (
                self._kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P384_SHA384  # noqa: E501
            )
            digest_obj = self._kms.Digest(sha384=data)
        else:
            algorithm = (
                self._kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P521_SHA512  # noqa: E501
            )
            digest_obj = self._kms.Digest(sha512=data)

        crypto_key_version = self._kms_client.get_crypto_key_version(
            name=f"{self._key_path}/cryptoKeyVersions/1"
        )
        if crypto_key_version.algorithm != algorithm:
            raise ValueError("Key algorithm mismatch")

        response = self._kms_client.asymmetric_sign(
            name=f"{self._key_path}/cryptoKeyVersions/1", digest=digest_obj
        )
        sig_bytes = response.signature
        return DSASignature.from_p1363(sig_bytes).dump()

    def get_public_key(self) -> ec.EllipticCurvePublicKey:
        return self._public_key


class AzureKMSBackend(KMSBackend):
    """Azure Key Vault backend."""

    def __init__(
        self, vault_url: str, key_name: str, key_version: str | None = None
    ):
        """Initializes the Azure Key Vault backend.

        Args:
            vault_url: The Azure Key Vault URL
                (e.g., 'https://vault.vault.azure.net').
            key_name: The key name.
            key_version: Optional key version. If not provided, uses the
                latest version.
        """
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.keys import KeyClient
            from azure.keyvault.keys.crypto import CryptographyClient
        except ImportError as e:
            raise RuntimeError(
                "Azure KMS support requires 'azure-keyvault-keys' and "
                "'azure-identity'. Install with "
                "'pip install azure-keyvault-keys azure-identity'."
            ) from e

        self._vault_url = vault_url
        self._key_name = key_name
        self._key_version = key_version
        credential = DefaultAzureCredential()
        self._key_client = KeyClient(vault_url=vault_url, credential=credential)
        self._crypto_client = CryptographyClient(
            key=self._key_client.get_key(key_name, version=key_version),
            credential=credential,
        )
        self._public_key = self._get_public_key()

    def _get_public_key(self) -> ec.EllipticCurvePublicKey:
        key = self._key_client.get_key(
            self._key_name, version=self._key_version
        )
        if key.key_type not in ["EC", "EC-HSM"]:
            raise ValueError("Only elliptic curve keys are supported")

        public_key_jwk = key.key
        x_str = public_key_jwk["x"]
        y_str = public_key_jwk["y"]
        missing_padding_x = len(x_str) % 4
        missing_padding_y = len(y_str) % 4
        if missing_padding_x:
            x_str += "=" * (4 - missing_padding_x)
        if missing_padding_y:
            y_str += "=" * (4 - missing_padding_y)
        x = base64.urlsafe_b64decode(x_str)
        y = base64.urlsafe_b64decode(y_str)

        curve_name = public_key_jwk.get("crv", "").upper()
        if curve_name == "P-256":
            curve = ec.SECP256R1()
        elif curve_name == "P-384":
            curve = ec.SECP384R1()
        elif curve_name == "P-521":
            curve = ec.SECP521R1()
        else:
            raise ValueError(f"Unsupported curve: {curve_name}")

        public_numbers = ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(x, "big"), y=int.from_bytes(y, "big"), curve=curve
        )  # noqa: E501
        public_key = public_numbers.public_key()
        _check_supported_ec_key(public_key)
        return public_key

    def sign(self, data: bytes, is_digest: bool = False) -> bytes:
        if not is_digest:
            raise ValueError("Azure KMS requires pre-hashed digest")
        hash_alg = ec_key.get_ec_key_hash(self._public_key)
        if hash_alg.name == "sha256":
            algorithm = "ES256"
        elif hash_alg.name == "sha384":
            algorithm = "ES384"
        else:
            algorithm = "ES512"

        result = self._crypto_client.sign(algorithm, data)
        return DSASignature.from_p1363(result.signature).dump()

    def get_public_key(self) -> ec.EllipticCurvePublicKey:
        return self._public_key


def _parse_kms_uri(kms_uri: str) -> tuple[str, dict[str, str]]:
    """Parses a KMS URI into provider and parameters.

    Supported formats:
    - kms://file/<path>
    - kms://aws/<key-id-or-arn>?region=<region>
    - kms://gcp/<project>/<location>/<keyring>/<key>
    - kms://azure/<vault-url>/<key-name>?version=<version>

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
    if provider == "file":
        if len(path_parts) == 0:
            raise ValueError("File KMS URI must have format: kms://file/<path>")
        path_str = "/".join(path_parts)
        is_windows_path = (
            len(path_parts) > 0
            and len(path_parts[0]) == 2
            and path_parts[0][1] == ":"
        )
        if (
            not is_windows_path
            and parsed.path.startswith("/")
            and not path_str.startswith("/")
        ):
            path_str = "/" + path_str
        params["path"] = path_str
    elif provider == "aws":
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
                    "arn:aws:kms:<region>:<account-id>:key/<key-id>"  # noqa: E501
                )
        elif "/" in key_id:
            raise ValueError(
                "AWS KMS URI must be either a full ARN "
                "(arn:aws:kms:...) or a simple key ID"
            )
        params["key_id"] = key_id
        if "region" in query_params:
            params["region"] = query_params["region"][0]
    elif provider == "gcp":
        if len(path_parts) != 4:
            raise ValueError(
                "GCP KMS URI must have format: "
                "kms://gcp/<project>/<location>/<keyring>/<key>"
            )
        params["project_id"] = path_parts[0]
        params["location"] = path_parts[1]
        params["keyring"] = path_parts[2]
        params["key_name"] = path_parts[3]
    elif provider == "azure":
        if len(path_parts) < 2:
            raise ValueError(
                "Azure KMS URI must have format: "
                "kms://azure/<vault-url>/<key-name>"
            )
        vault_url = path_parts[0]
        if not vault_url.startswith("http://") and not vault_url.startswith(
            "https://"
        ):
            vault_url = f"https://{vault_url}"
        params["vault_url"] = vault_url
        params["key_name"] = path_parts[1]
        if "version" in query_params:
            params["version"] = query_params["version"][0]
    else:
        raise ValueError(f"Unsupported KMS provider: {provider}")

    return provider, params


class Signer(sigstore_pb.Signer):
    """Signer using KMS URIs with elliptic curve keys."""

    def __init__(self, kms_uri: str):
        """Initializes the KMS signer.

        Args:
            kms_uri: The KMS URI specifying the provider and key.
        """
        provider, params = _parse_kms_uri(kms_uri)

        if provider == "file":
            self._backend = FileKMSBackend(pathlib.Path(params["path"]))
        elif provider == "aws":
            self._backend = AWSKMSBackend(
                params["key_id"], params.get("region")
            )
        elif provider == "gcp":
            self._backend = GCPKMSBackend(
                params["project_id"],
                params["location"],
                params["keyring"],
                params["key_name"],
            )
        elif provider == "azure":
            self._backend = AzureKMSBackend(
                params["vault_url"], params["key_name"], params.get("version")
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

        if isinstance(self._backend, FileKMSBackend):
            sig = self._backend.sign(pae_payload, is_digest=False)
        else:
            hash_obj = hashes.Hash(hash_alg)
            hash_obj.update(pae_payload)
            digest = hash_obj.finalize()
            sig = self._backend.sign(digest, is_digest=True)

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
