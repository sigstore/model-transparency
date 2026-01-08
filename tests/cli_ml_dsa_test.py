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
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for ML-DSA CLI commands."""

from pathlib import Path
from tempfile import TemporaryDirectory
import subprocess
import sys

import pytest


@pytest.fixture
def populate_tmpdir(tmp_path: Path) -> Path:
    """Create a temporary directory with test files."""
    Path(tmp_path / "signme-1").write_text("signme-1")
    Path(tmp_path / "signme-2").write_text("signme-2")
    Path(tmp_path / ".gitignore").write_text(".foo")
    return tmp_path


class TestMLDSACLI:
    """Tests for ML-DSA command line interface."""

    def test_sign_ml_dsa_basic(self, populate_tmpdir):
        """Test basic ML-DSA signing via CLI."""
        from dilithium_py.ml_dsa import ML_DSA_65

        ml_dsa = ML_DSA_65
        model_path = populate_tmpdir

        with TemporaryDirectory() as tmpdir:
            private_key = Path(tmpdir) / "test.priv"
            public_key = Path(tmpdir) / "test.pub"
            signature = Path(tmpdir) / "model.sig"

            # Generate key pair
            pk, sk = ml_dsa.keygen()
            private_key.write_bytes(sk)
            public_key.write_bytes(pk)

            # Sign using CLI
            result = subprocess.run(
                [
                    sys.executable, "-m", "model_signing",
                    "sign", "ml-dsa", str(model_path),
                    "--private_key", str(private_key),
                    "--signature", str(signature),
                ],
                capture_output=True,
                text=True,
            )

            assert result.returncode == 0, f"Sign failed: {result.stderr}"
            assert signature.exists(), "Signature file not created"

            # Verify using CLI
            result = subprocess.run(
                [
                    sys.executable, "-m", "model_signing",
                    "verify", "ml-dsa", str(model_path),
                    "--public_key", str(public_key),
                    "--signature", str(signature),
                ],
                capture_output=True,
                text=True,
            )

            assert result.returncode == 0, f"Verify failed: {result.stderr}"

    def test_sign_ml_dsa_with_password(self, populate_tmpdir):
        """Test ML-DSA signing with encrypted key via CLI."""
        from dilithium_py.ml_dsa import ML_DSA_65
        from model_signing._signing.sign_ml_dsa import encrypt_private_key

        ml_dsa = ML_DSA_65
        model_path = populate_tmpdir
        password = "test_cli_password_123"

        with TemporaryDirectory() as tmpdir:
            private_key = Path(tmpdir) / "test.priv"
            public_key = Path(tmpdir) / "test.pub"
            encrypted_key = Path(tmpdir) / "test_encrypted.priv"
            signature = Path(tmpdir) / "model.sig"

            # Generate and encrypt key pair
            pk, sk = ml_dsa.keygen()
            private_key.write_bytes(sk)
            public_key.write_bytes(pk)
            encrypted_data = encrypt_private_key(sk, password)
            encrypted_key.write_bytes(encrypted_data)

            # Sign using CLI with password
            result = subprocess.run(
                [
                    sys.executable, "-m", "model_signing",
                    "sign", "ml-dsa", str(model_path),
                    "--private_key", str(encrypted_key),
                    "--password", password,
                    "--signature", str(signature),
                ],
                capture_output=True,
                text=True,
            )

            assert result.returncode == 0, f"Sign failed: {result.stderr}"
            assert signature.exists(), "Signature file not created"

            # Verify using CLI
            result = subprocess.run(
                [
                    sys.executable, "-m", "model_signing",
                    "verify", "ml-dsa", str(model_path),
                    "--public_key", str(public_key),
                    "--signature", str(signature),
                ],
                capture_output=True,
                text=True,
            )

            assert result.returncode == 0, f"Verify failed: {result.stderr}"

    def test_sign_ml_dsa_wrong_password(self, populate_tmpdir):
        """Test ML-DSA signing with wrong password fails."""
        from dilithium_py.ml_dsa import ML_DSA_44
        from model_signing._signing.sign_ml_dsa import encrypt_private_key

        ml_dsa = ML_DSA_44
        model_path = populate_tmpdir
        correct_password = "correct_password"
        wrong_password = "wrong_password"

        with TemporaryDirectory() as tmpdir:
            encrypted_key = Path(tmpdir) / "test_encrypted.priv"
            signature = Path(tmpdir) / "model.sig"

            # Generate and encrypt key
            pk, sk = ml_dsa.keygen()
            encrypted_data = encrypt_private_key(sk, correct_password)
            encrypted_key.write_bytes(encrypted_data)

            # Try to sign with wrong password
            result = subprocess.run(
                [
                    sys.executable, "-m", "model_signing",
                    "sign", "ml-dsa", str(model_path),
                    "--private_key", str(encrypted_key),
                    "--password", wrong_password,
                    "--signature", str(signature),
                ],
                capture_output=True,
                text=True,
            )

            assert result.returncode != 0, "Should fail with wrong password"
            assert "Invalid password" in result.stderr or "password" in result.stderr.lower()

    def test_sign_ml_dsa_encrypted_no_password(self, populate_tmpdir):
        """Test that encrypted key without password fails."""
        from dilithium_py.ml_dsa import ML_DSA_87
        from model_signing._signing.sign_ml_dsa import encrypt_private_key

        ml_dsa = ML_DSA_87
        model_path = populate_tmpdir
        password = "test_password"

        with TemporaryDirectory() as tmpdir:
            encrypted_key = Path(tmpdir) / "test_encrypted.priv"
            signature = Path(tmpdir) / "model.sig"

            # Generate and encrypt key
            pk, sk = ml_dsa.keygen()
            encrypted_data = encrypt_private_key(sk, password)
            encrypted_key.write_bytes(encrypted_data)

            # Try to sign without password
            result = subprocess.run(
                [
                    sys.executable, "-m", "model_signing",
                    "sign", "ml-dsa", str(model_path),
                    "--private_key", str(encrypted_key),
                    "--signature", str(signature),
                ],
                capture_output=True,
                text=True,
            )

            assert result.returncode != 0, "Should fail without password"
            assert "Password required" in result.stderr or "password" in result.stderr.lower()

    def test_sign_ml_dsa_all_variants(self, populate_tmpdir):
        """Test all ML-DSA variants via CLI."""
        from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87

        model_path = populate_tmpdir

        variants = [
            ("ML_DSA_44", ML_DSA_44),
            ("ML_DSA_65", ML_DSA_65),
            ("ML_DSA_87", ML_DSA_87),
        ]

        for variant_name, ml_dsa in variants:
            with TemporaryDirectory() as tmpdir:
                private_key = Path(tmpdir) / "test.priv"
                public_key = Path(tmpdir) / "test.pub"
                signature = Path(tmpdir) / "model.sig"

                # Generate key pair
                pk, sk = ml_dsa.keygen()
                private_key.write_bytes(sk)
                public_key.write_bytes(pk)

                # Sign using CLI with variant option
                result = subprocess.run(
                    [
                        sys.executable, "-m", "model_signing",
                        "sign", "ml-dsa", str(model_path),
                        "--private_key", str(private_key),
                        "--variant", variant_name,
                        "--signature", str(signature),
                    ],
                    capture_output=True,
                    text=True,
                )

                assert result.returncode == 0, f"Sign failed for {variant_name}: {result.stderr}"
                assert signature.exists(), f"Signature not created for {variant_name}"

                # Verify using CLI with variant option
                result = subprocess.run(
                    [
                        sys.executable, "-m", "model_signing",
                        "verify", "ml-dsa", str(model_path),
                        "--public_key", str(public_key),
                        "--variant", variant_name,
                        "--signature", str(signature),
                    ],
                    capture_output=True,
                    text=True,
                )

                assert result.returncode == 0, f"Verify failed for {variant_name}: {result.stderr}"

    def test_verify_ml_dsa_invalid_signature(self, populate_tmpdir):
        """Test that verification fails with tampered signature."""
        from dilithium_py.ml_dsa import ML_DSA_65

        ml_dsa = ML_DSA_65
        model_path = populate_tmpdir

        with TemporaryDirectory() as tmpdir:
            private_key = Path(tmpdir) / "test.priv"
            public_key = Path(tmpdir) / "test.pub"
            signature = Path(tmpdir) / "model.sig"

            # Generate key pair
            pk, sk = ml_dsa.keygen()
            private_key.write_bytes(sk)
            public_key.write_bytes(pk)

            # Sign using CLI
            result = subprocess.run(
                [
                    sys.executable, "-m", "model_signing",
                    "sign", "ml-dsa", str(model_path),
                    "--private_key", str(private_key),
                    "--signature", str(signature),
                ],
                capture_output=True,
                text=True,
            )

            assert result.returncode == 0

            # Tamper with the model
            tamper_file = Path(model_path) / "signme-1"
            tamper_file.write_text("tampered content")

            # Verify should fail
            result = subprocess.run(
                [
                    sys.executable, "-m", "model_signing",
                    "verify", "ml-dsa", str(model_path),
                    "--public_key", str(public_key),
                    "--signature", str(signature),
                ],
                capture_output=True,
                text=True,
            )

            assert result.returncode != 0, "Verification should fail with tampered content"

    def test_sign_ml_dsa_with_ignore_paths(self, populate_tmpdir):
        """Test ML-DSA signing with ignored paths via CLI."""
        from dilithium_py.ml_dsa import ML_DSA_65

        ml_dsa = ML_DSA_65
        model_path = populate_tmpdir

        # Create a file to ignore
        ignore_file = Path(model_path) / "ignore_me.txt"
        ignore_file.write_text("This should be ignored")

        with TemporaryDirectory() as tmpdir:
            private_key = Path(tmpdir) / "test.priv"
            public_key = Path(tmpdir) / "test.pub"
            signature = Path(tmpdir) / "model.sig"

            # Generate key pair
            pk, sk = ml_dsa.keygen()
            private_key.write_bytes(sk)
            public_key.write_bytes(pk)

            # Sign with ignored paths
            result = subprocess.run(
                [
                    sys.executable, "-m", "model_signing",
                    "sign", "ml-dsa", str(model_path),
                    "--private_key", str(private_key),
                    "--signature", str(signature),
                    "--ignore-paths", str(ignore_file),
                    "--ignore-paths", str(signature),
                ],
                capture_output=True,
                text=True,
            )

            assert result.returncode == 0, f"Sign failed: {result.stderr}"

            # Verify
            result = subprocess.run(
                [
                    sys.executable, "-m", "model_signing",
                    "verify", "ml-dsa", str(model_path),
                    "--public_key", str(public_key),
                    "--signature", str(signature),
                    "--ignore-paths", str(ignore_file),
                    "--ignore-paths", str(signature),
                ],
                capture_output=True,
                text=True,
            )

            assert result.returncode == 0, f"Verify failed: {result.stderr}"

            # Modify ignored file - should still verify
            ignore_file.write_text("Modified but ignored")

            result = subprocess.run(
                [
                    sys.executable, "-m", "model_signing",
                    "verify", "ml-dsa", str(model_path),
                    "--public_key", str(public_key),
                    "--signature", str(signature),
                    "--ignore-paths", str(ignore_file),
                    "--ignore-paths", str(signature),
                ],
                capture_output=True,
                text=True,
            )

            assert result.returncode == 0, "Verify should succeed with modified ignored file"

    def test_sign_ml_dsa_default_signature_path(self, populate_tmpdir):
        """Test ML-DSA signing with default signature path."""
        from dilithium_py.ml_dsa import ML_DSA_65

        ml_dsa = ML_DSA_65
        model_path = populate_tmpdir

        with TemporaryDirectory() as tmpdir:
            private_key = Path(tmpdir) / "test.priv"
            public_key = Path(tmpdir) / "test.pub"
            default_signature = Path(tmpdir) / "model.sig"

            # Generate key pair
            pk, sk = ml_dsa.keygen()
            private_key.write_bytes(sk)
            public_key.write_bytes(pk)

            # Sign without specifying signature path (should use default in cwd)
            result = subprocess.run(
                [
                    sys.executable, "-m", "model_signing",
                    "sign", "ml-dsa", str(model_path),
                    "--private_key", str(private_key),
                ],
                capture_output=True,
                text=True,
                cwd=tmpdir,  # Run from tmpdir, so model.sig will be created there
            )

            assert result.returncode == 0, f"Sign failed: {result.stderr}"

            # Default signature should be in cwd as model.sig
            assert default_signature.exists(), "Default signature file not created"

            # Verify with default signature
            result = subprocess.run(
                [
                    sys.executable, "-m", "model_signing",
                    "verify", "ml-dsa", str(model_path),
                    "--public_key", str(public_key),
                    "--signature", str(default_signature),
                ],
                capture_output=True,
                text=True,
            )

            assert result.returncode == 0, f"Verify failed: {result.stderr}"

            # Clean up
            default_signature.unlink()
