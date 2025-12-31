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

"""Tests for ML-DSA (post-quantum) signing and verification."""

import pathlib

import pytest

from model_signing._signing import sign_ml_dsa as ml_dsa
from model_signing._signing import signing


# Check if dilithium-py is available
pytest.importorskip("dilithium_py")


class TestMLDSASigner:
    """Tests for ML-DSA signer."""

    @pytest.fixture
    def ml_dsa_keys(self, tmp_path):
        """Generate ML-DSA-65 key pair for testing."""
        from dilithium_py.ml_dsa import ML_DSA_65

        public_key, private_key = ML_DSA_65.keygen()

        pk_path = tmp_path / "ml_dsa_65.pub"
        sk_path = tmp_path / "ml_dsa_65.priv"

        pk_path.write_bytes(public_key)
        sk_path.write_bytes(private_key)

        return pk_path, sk_path

    def test_signer_initialization(self, ml_dsa_keys):
        """Test that ML-DSA signer can be initialized."""
        _, sk_path = ml_dsa_keys
        signer = ml_dsa.Signer(sk_path, "ML_DSA_65")
        assert signer is not None

    def test_signer_all_variants(self, tmp_path):
        """Test all ML-DSA security levels."""
        from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87

        variants = {
            "ML_DSA_44": ML_DSA_44,
            "ML_DSA_65": ML_DSA_65,
            "ML_DSA_87": ML_DSA_87,
        }

        for variant_name, variant_impl in variants.items():
            pk, sk = variant_impl.keygen()
            sk_path = tmp_path / f"{variant_name}.priv"
            sk_path.write_bytes(sk)

            signer = ml_dsa.Signer(sk_path, variant_name)
            assert signer is not None
            assert signer._variant_name == variant_name

    def test_sign_creates_signature(self, ml_dsa_keys, sample_model_folder):
        """Test that signing creates a valid signature."""
        from model_signing import hashing
        from model_signing import manifest as manifest_mod

        _, sk_path = ml_dsa_keys

        # Create a manifest
        hash_config = hashing.Config()
        model_manifest = hash_config.hash(sample_model_folder)

        # Create payload
        payload = signing.Payload(model_manifest)

        # Sign
        signer = ml_dsa.Signer(sk_path, "ML_DSA_65")
        signature = signer.sign(payload)

        assert signature is not None
        assert isinstance(signature, signing.Signature)

    def test_signature_contains_verification_material(
        self, ml_dsa_keys, sample_model_folder
    ):
        """Test that signature includes verification material."""
        from model_signing import hashing

        _, sk_path = ml_dsa_keys

        # Create manifest and sign
        model_manifest = hashing.Config().hash(sample_model_folder)
        payload = signing.Payload(model_manifest)
        signer = ml_dsa.Signer(sk_path, "ML_DSA_65")
        signature = signer.sign(payload)

        # Check bundle structure
        assert hasattr(signature, "bundle")
        bundle = signature.bundle
        assert bundle.verification_material is not None
        assert bundle.verification_material.public_key is not None


class TestMLDSAVerifier:
    """Tests for ML-DSA verifier."""

    @pytest.fixture
    def ml_dsa_keys(self, tmp_path):
        """Generate ML-DSA-65 key pair for testing."""
        from dilithium_py.ml_dsa import ML_DSA_65

        public_key, private_key = ML_DSA_65.keygen()

        pk_path = tmp_path / "ml_dsa_65.pub"
        sk_path = tmp_path / "ml_dsa_65.priv"

        pk_path.write_bytes(public_key)
        sk_path.write_bytes(private_key)

        return pk_path, sk_path

    def test_verifier_initialization(self, ml_dsa_keys):
        """Test that ML-DSA verifier can be initialized."""
        pk_path, _ = ml_dsa_keys
        verifier = ml_dsa.Verifier(pk_path, "ML_DSA_65")
        assert verifier is not None

    def test_verify_valid_signature(self, ml_dsa_keys, sample_model_folder):
        """Test that a valid signature verifies successfully."""
        from model_signing import hashing

        pk_path, sk_path = ml_dsa_keys

        # Create and sign
        model_manifest = hashing.Config().hash(sample_model_folder)
        payload = signing.Payload(model_manifest)
        signer = ml_dsa.Signer(sk_path, "ML_DSA_65")
        signature = signer.sign(payload)

        # Verify
        verifier = ml_dsa.Verifier(pk_path, "ML_DSA_65")
        payload_type, raw_payload = verifier._verify_bundle(signature.bundle)

        assert payload_type == signing._IN_TOTO_JSON_PAYLOAD_TYPE
        assert raw_payload is not None

    def test_verify_invalid_signature_fails(
        self, ml_dsa_keys, sample_model_folder
    ):
        """Test that verification fails with wrong public key."""
        from dilithium_py.ml_dsa import ML_DSA_65
        from model_signing import hashing

        pk_path, sk_path = ml_dsa_keys

        # Create another key pair
        wrong_pk, _ = ML_DSA_65.keygen()
        wrong_pk_path = pk_path.parent / "wrong.pub"
        wrong_pk_path.write_bytes(wrong_pk)

        # Sign with original key
        model_manifest = hashing.Config().hash(sample_model_folder)
        payload = signing.Payload(model_manifest)
        signer = ml_dsa.Signer(sk_path, "ML_DSA_65")
        signature = signer.sign(payload)

        # Try to verify with wrong key (should fail with key mismatch error)
        verifier = ml_dsa.Verifier(wrong_pk_path, "ML_DSA_65")

        with pytest.raises(ValueError, match="Key mismatch"):
            verifier._verify_bundle(signature.bundle)

    def test_roundtrip_sign_and_verify(self, ml_dsa_keys, sample_model_folder):
        """Test complete sign and verify roundtrip."""
        from model_signing import hashing

        pk_path, sk_path = ml_dsa_keys

        # Sign
        model_manifest = hashing.Config().hash(sample_model_folder)
        payload = signing.Payload(model_manifest)
        signer = ml_dsa.Signer(sk_path, "ML_DSA_65")
        signature = signer.sign(payload)

        # Verify
        verifier = ml_dsa.Verifier(pk_path, "ML_DSA_65")
        restored_manifest = verifier.verify(signature)

        # Compare manifests
        assert restored_manifest == model_manifest


class TestMLDSAIntegration:
    """Integration tests for ML-DSA with model signing API."""

    @pytest.fixture
    def ml_dsa_keys(self, tmp_path):
        """Generate ML-DSA-65 key pair for testing."""
        from dilithium_py.ml_dsa import ML_DSA_65

        public_key, private_key = ML_DSA_65.keygen()

        pk_path = tmp_path / "ml_dsa_65.pub"
        sk_path = tmp_path / "ml_dsa_65.priv"

        pk_path.write_bytes(public_key)
        sk_path.write_bytes(private_key)

        return pk_path, sk_path

    def test_api_sign_and_verify(
        self, ml_dsa_keys, sample_model_folder, tmp_path
    ):
        """Test signing and verification through public API."""
        from model_signing import signing as signing_api
        from model_signing import verifying

        pk_path, sk_path = ml_dsa_keys
        sig_path = tmp_path / "model.sig"

        # Sign using API
        signing_api.Config().use_ml_dsa_signer(
            private_key=sk_path, variant="ML_DSA_65"
        ).sign(sample_model_folder, sig_path)

        assert sig_path.exists()

        # Verify using API
        verifying.Config().use_ml_dsa_verifier(
            public_key=pk_path, variant="ML_DSA_65"
        ).verify(sample_model_folder, sig_path)

    def test_signature_persistence(
        self, ml_dsa_keys, sample_model_folder, tmp_path
    ):
        """Test that signature can be written and read from disk."""
        from model_signing import signing as signing_api
        from model_signing import verifying

        pk_path, sk_path = ml_dsa_keys
        sig_path = tmp_path / "model.sig"

        # Sign and save
        signing_api.Config().use_ml_dsa_signer(
            private_key=sk_path, variant="ML_DSA_65"
        ).sign(sample_model_folder, sig_path)

        # Check file exists and is not empty
        assert sig_path.exists()
        assert sig_path.stat().st_size > 0

        # Verify from saved file
        verifying.Config().use_ml_dsa_verifier(
            public_key=pk_path, variant="ML_DSA_65"
        ).verify(sample_model_folder, sig_path)

    def test_different_variants_interoperability(
        self, tmp_path, sample_model_folder
    ):
        """Test that different ML-DSA variants work correctly."""
        from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_87
        from model_signing import signing as signing_api
        from model_signing import verifying

        # Test ML_DSA_44
        pk_44, sk_44 = ML_DSA_44.keygen()
        pk_44_path = tmp_path / "ml_dsa_44.pub"
        sk_44_path = tmp_path / "ml_dsa_44.priv"
        pk_44_path.write_bytes(pk_44)
        sk_44_path.write_bytes(sk_44)
        sig_44_path = tmp_path / "model_44.sig"

        signing_api.Config().use_ml_dsa_signer(
            private_key=sk_44_path, variant="ML_DSA_44"
        ).sign(sample_model_folder, sig_44_path)

        verifying.Config().use_ml_dsa_verifier(
            public_key=pk_44_path, variant="ML_DSA_44"
        ).verify(sample_model_folder, sig_44_path)

        # Test ML_DSA_87
        pk_87, sk_87 = ML_DSA_87.keygen()
        pk_87_path = tmp_path / "ml_dsa_87.pub"
        sk_87_path = tmp_path / "ml_dsa_87.priv"
        pk_87_path.write_bytes(pk_87)
        sk_87_path.write_bytes(sk_87)
        sig_87_path = tmp_path / "model_87.sig"

        signing_api.Config().use_ml_dsa_signer(
            private_key=sk_87_path, variant="ML_DSA_87"
        ).sign(sample_model_folder, sig_87_path)

        verifying.Config().use_ml_dsa_verifier(
            public_key=pk_87_path, variant="ML_DSA_87"
        ).verify(sample_model_folder, sig_87_path)
