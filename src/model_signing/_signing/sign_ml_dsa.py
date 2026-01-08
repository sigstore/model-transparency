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

"""Signers and verifiers using ML-DSA (post-quantum cryptography)."""

import base64
import hashlib
import os
import pathlib
from typing import Literal

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from google.protobuf import json_format
from sigstore_models import intoto as intoto_pb
from sigstore_models.bundle import v1 as bundle_pb
from sigstore_models.common import v1 as common_pb
from typing_extensions import override

from model_signing._signing import sign_sigstore_pb as sigstore_pb
from model_signing._signing import signing


# Type alias for ML-DSA variants
MLDSAVariant = Literal["ML_DSA_44", "ML_DSA_65", "ML_DSA_87"]


# Magic header for encrypted ML-DSA keys
_ENCRYPTED_KEY_HEADER = b"MLDSA-ENC-V1"
_SALT_SIZE = 16
_NONCE_SIZE = 12
_KDF_ITERATIONS = 100000


def _derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derives an encryption key from a password using PBKDF2.

    Args:
        password: The password to derive the key from.
        salt: Random salt for key derivation.

    Returns:
        A 32-byte AES-256 key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_private_key(private_key: bytes, password: str) -> bytes:
    """Encrypts an ML-DSA private key with a password.

    The encrypted format is:
    [MAGIC_HEADER (12 bytes)][SALT (16 bytes)][NONCE (12 bytes)][CIPHERTEXT + TAG]

    Args:
        private_key: The raw ML-DSA private key bytes.
        password: The password to encrypt with.

    Returns:
        Encrypted key bytes.
    """
    # Generate random salt and nonce
    salt = os.urandom(_SALT_SIZE)
    nonce = os.urandom(_NONCE_SIZE)

    # Derive encryption key from password
    key = _derive_key_from_password(password, salt)

    # Encrypt using AES-256-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, private_key, None)

    # Combine header, salt, nonce, and ciphertext
    return _ENCRYPTED_KEY_HEADER + salt + nonce + ciphertext


def decrypt_private_key(encrypted_data: bytes, password: str) -> bytes:
    """Decrypts an ML-DSA private key with a password.

    Args:
        encrypted_data: The encrypted key data.
        password: The password to decrypt with.

    Returns:
        Decrypted private key bytes.

    Raises:
        ValueError: If the data format is invalid or password is incorrect.
    """
    # Check minimum size
    min_size = len(_ENCRYPTED_KEY_HEADER) + _SALT_SIZE + _NONCE_SIZE + 16
    if len(encrypted_data) < min_size:
        raise ValueError("Invalid encrypted key format: data too short")

    # Parse header
    header = encrypted_data[: len(_ENCRYPTED_KEY_HEADER)]
    if header != _ENCRYPTED_KEY_HEADER:
        raise ValueError(
            "Invalid encrypted key format: incorrect magic header. "
            "This may not be an encrypted ML-DSA key."
        )

    # Parse salt and nonce
    offset = len(_ENCRYPTED_KEY_HEADER)
    salt = encrypted_data[offset : offset + _SALT_SIZE]
    offset += _SALT_SIZE
    nonce = encrypted_data[offset : offset + _NONCE_SIZE]
    offset += _NONCE_SIZE
    ciphertext = encrypted_data[offset:]

    # Derive decryption key
    key = _derive_key_from_password(password, salt)

    # Decrypt using AES-256-GCM
    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext
    except Exception as e:
        raise ValueError(
            "Failed to decrypt key: incorrect password or corrupted data"
        ) from e


def _get_ml_dsa_variant(variant: MLDSAVariant):
    """Returns the ML-DSA implementation for the specified variant.

    Args:
        variant: The ML-DSA security level to use.

    Returns:
        The ML-DSA class instance for the variant.

    Raises:
        ImportError: If dilithium-py is not installed.
        ValueError: If the variant is not supported.
    """
    try:
        from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
    except ImportError as e:
        raise ImportError(
            "ML-DSA support requires 'dilithium-py' package. "
            "Install it with: pip install dilithium-py"
        ) from e

    variants = {
        "ML_DSA_44": ML_DSA_44,
        "ML_DSA_65": ML_DSA_65,
        "ML_DSA_87": ML_DSA_87,
    }

    if variant not in variants:
        raise ValueError(
            f"Unsupported ML-DSA variant: {variant}. "
            f"Supported variants: {list(variants.keys())}"
        )

    return variants[variant]


def _get_public_key_details(variant: MLDSAVariant) -> str:
    """Returns the PublicKeyDetails enum value for the ML-DSA variant.

    Args:
        variant: The ML-DSA security level.

    Returns:
        The string representation of the PublicKeyDetails enum.
    """
    # Map to sigstore_models PublicKeyDetails enum values
    variant_map = {
        "ML_DSA_44": "ML_DSA_44",  # Not yet in official spec
        "ML_DSA_65": "ML_DSA_65",
        "ML_DSA_87": "ML_DSA_87",
    }
    return variant_map[variant]


class Signer(sigstore_pb.Signer):
    """Signer using ML-DSA post-quantum cryptography."""

    def __init__(
        self,
        private_key_path: pathlib.Path,
        variant: MLDSAVariant = "ML_DSA_65",
        password: str | None = None,
    ):
        """Initializes the ML-DSA signer with a private key.

        Args:
            private_key_path: Path to the ML-DSA private key (raw bytes or encrypted).
            variant: The ML-DSA security level (ML_DSA_44, ML_DSA_65, or ML_DSA_87).
                    Default is ML_DSA_65 (NIST security level 3).
            password: Optional password if the private key is encrypted.

        Raises:
            ImportError: If dilithium-py is not installed.
            ValueError: If the variant is not supported or decryption fails.
        """
        self._variant_name = variant
        self._ml_dsa = _get_ml_dsa_variant(variant)

        # Read key data
        key_data = private_key_path.read_bytes()

        # Check if key is encrypted and decrypt if needed
        if key_data.startswith(_ENCRYPTED_KEY_HEADER):
            if password is None:
                raise ValueError(
                    "Private key is encrypted but no password provided. "
                    "Please provide a password using the --password option."
                )
            self._private_key = decrypt_private_key(key_data, password)
        else:
            # Raw key - password should not be provided
            if password is not None:
                raise ValueError(
                    "Password provided but private key is not encrypted. "
                    "Remove the --password option or encrypt the key first."
                )
            self._private_key = key_data

        # Derive public key from private key for verification material
        self._public_key = self._ml_dsa.pk_from_sk(self._private_key)

    @override
    def sign(self, payload: signing.Payload) -> signing.Signature:
        """Signs the payload using ML-DSA.

        Args:
            payload: The payload to sign (contains in-toto statement).

        Returns:
            A Sigstore bundle containing the ML-DSA signature.
        """
        # Serialize the in-toto statement to JSON
        raw_payload = json_format.MessageToJson(payload.statement.pb).encode(
            "utf-8"
        )

        # Generate PAE (Pre-Authentication Encoding) for DSSE
        pae = sigstore_pb.pae(raw_payload)

        # Sign using ML-DSA
        # Note: ML-DSA sign takes the message directly, not a hash
        raw_signature = self._ml_dsa.sign(self._private_key, pae)

        # Create DSSE signature structure
        dsse_signature = intoto_pb.Signature(
            sig=base64.b64encode(raw_signature),
            keyid="",  # Not used for ML-DSA
        )

        # Create DSSE envelope
        envelope = intoto_pb.Envelope(
            payload=base64.b64encode(raw_payload),
            payload_type=signing._IN_TOTO_JSON_PAYLOAD_TYPE,
            signatures=[dsse_signature],
        )

        # Create Sigstore bundle
        bundle = bundle_pb.Bundle(
            media_type=sigstore_pb._BUNDLE_MEDIA_TYPE,
            verification_material=self._get_verification_material(),
            dsse_envelope=envelope,
        )

        return sigstore_pb.Signature(bundle)

    def _get_verification_material(self) -> bundle_pb.VerificationMaterial:
        """Returns the verification material for the Sigstore bundle.

        Returns:
            VerificationMaterial containing the ML-DSA public key.
        """
        # Encode public key as base64
        raw_bytes = base64.b64encode(self._public_key).decode("ascii")

        # Create hash hint for key identification
        hash_bytes = hashlib.sha256(self._public_key).digest().hex()

        # Note: ML_DSA_65 is not yet officially in sigstore_models.common.v1.PublicKeyDetails
        # For now, we'll store it as a hint in the publicKey structure
        return bundle_pb.VerificationMaterial(
            public_key=common_pb.PublicKeyIdentifier(
                hint=f"{self._variant_name}:{hash_bytes}"
            ),
            tlog_entries=[],
        )


class Verifier(sigstore_pb.Verifier):
    """Verifier for ML-DSA post-quantum signatures."""

    def __init__(
        self,
        public_key_path: pathlib.Path,
        variant: MLDSAVariant = "ML_DSA_65",
    ):
        """Initializes the ML-DSA verifier with a public key.

        Args:
            public_key_path: Path to the ML-DSA public key (raw bytes).
            variant: The ML-DSA security level (must match the signing key).

        Raises:
            ImportError: If dilithium-py is not installed.
            ValueError: If the variant is not supported.
        """
        self._variant_name = variant
        self._ml_dsa = _get_ml_dsa_variant(variant)
        self._public_key = public_key_path.read_bytes()

    @override
    def _verify_bundle(self, bundle: bundle_pb.Bundle) -> tuple[str, bytes]:
        """Verifies the ML-DSA signature in the bundle.

        Args:
            bundle: The Sigstore bundle to verify.

        Returns:
            A tuple of (payload_type, payload) if verification succeeds.

        Raises:
            ValueError: If signature verification fails or key mismatch detected.
        """
        # Verify public key hash matches (if hint is present)
        if bundle.verification_material.public_key.hint:
            hint = bundle.verification_material.public_key.hint
            if ":" in hint:
                variant_hint, hash_hint = hint.split(":", 1)
                expected_hash = hashlib.sha256(self._public_key).digest().hex()

                if hash_hint != expected_hash:
                    raise ValueError(
                        "Key mismatch: The public key hash in the signature's "
                        "verification material does not match the provided "
                        "public key."
                    )

                if variant_hint != self._variant_name:
                    print(
                        f"WARNING: Signature was created with {variant_hint} "
                        f"but verifying with {self._variant_name}. "
                        "This may cause verification to fail."
                    )

        # Extract envelope
        envelope = bundle.dsse_envelope

        # Decode the signature
        raw_signature = envelope.signatures[0].sig

        # Generate PAE for verification
        pae = sigstore_pb.pae(envelope.payload)

        # Verify using ML-DSA
        is_valid = self._ml_dsa.verify(self._public_key, pae, raw_signature)

        if not is_valid:
            # Try compatibility mode (for older signatures)
            try:
                pae_compat = sigstore_pb.pae_compat(envelope.payload)
                is_valid = self._ml_dsa.verify(
                    self._public_key, pae_compat, raw_signature
                )
            except Exception:
                pass

            if not is_valid:
                raise ValueError("ML-DSA signature verification failed")

        return envelope.payload_type, envelope.payload
