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

"""Tests for the top level API."""

from base64 import b64decode
from collections.abc import Iterable
from datetime import datetime
from datetime import timedelta
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import time

import pytest

from model_signing import hashing
from model_signing import signing
from model_signing import verifying


# Directory with testdata for this test
TESTDATA = Path(__file__).parent / "../scripts/tests"

# The default set of git related files that are ignored
GIT_IGNORE_PATHS: Iterable[str] = [
    ".git",
    ".gitattributes",
    ".gitignore",
    ".github",
]


@pytest.fixture
def base_path() -> Path:
    return Path(__file__).parent


@pytest.fixture
def populate_tmpdir(tmp_path: Path) -> Path:
    Path(tmp_path / "signme-1").write_text("signme-1")
    Path(tmp_path / "signme-2").write_text("signme-2")
    Path(tmp_path / ".gitignore").write_text(".foo")
    return tmp_path


def get_signed_files(modelsig: Path) -> list[str]:
    with open(modelsig, "r") as file:
        signature = json.load(file)
    payload = json.loads(b64decode(signature["dsseEnvelope"]["payload"]))
    return [entry["name"] for entry in payload["predicate"]["resources"]]


def get_ignore_paths(modelsig: Path) -> list[str]:
    with open(modelsig, "r") as file:
        signature = json.load(file)
    payload = json.loads(b64decode(signature["dsseEnvelope"]["payload"]))
    ignore_paths = payload["predicate"]["serialization"]["ignore_paths"]
    ignore_paths.sort()
    return ignore_paths


def check_ignore_paths(
    modelsig: Path,
    ignore_git_paths: bool,
    ignore_paths: Iterable[str] = frozenset(),
) -> None:
    ignore_paths = list(ignore_paths)
    if ignore_git_paths:
        ignore_paths += GIT_IGNORE_PATHS
    ignore_paths.sort()
    assert ignore_paths == get_ignore_paths(modelsig)


def get_model_name(modelsig: Path) -> str:
    with open(modelsig, "r") as file:
        signature = json.load(file)
    payload = json.loads(b64decode(signature["dsseEnvelope"]["payload"]))
    return payload["subject"][0]["name"]


_MIN_VALIDITY = timedelta(minutes=1)
_MAX_RETRY_TIME = timedelta(minutes=5)
_RETRY_SLEEP_SECS = 30


class DangerousPublicOIDCBeacon:
    """Fetches and validates tokens from Sigstore's testing beacon repo."""

    def __init__(self):
        self._token = ""

    def _fetch(self) -> None:
        # the git approach is apparently fresher than https://raw.githubusercontent.com
        # https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/issues/17
        git_url = "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon.git"
        with TemporaryDirectory() as tmpdir:
            base_cmd = [
                "git",
                "clone",
                "--quiet",
                "--single-branch",
                "--branch=current-token",
                "--depth=1",
            ]
            subprocess.run(base_cmd + [git_url, tmpdir], check=True)
            token_path = os.path.join(tmpdir, "oidc-token.txt")
            with open(token_path) as f:
                self._token = f.read().rstrip()

    def _expiration(self) -> datetime:
        payload = self._token.split(".")[1]
        payload += "=" * (4 - len(payload) % 4)
        payload_json = json.loads(b64decode(payload))
        return datetime.fromtimestamp(payload_json["exp"])


@pytest.fixture
def sigstore_oidc_beacon_token():
    beacon = DangerousPublicOIDCBeacon()
    start = datetime.now()
    while True:
        now = datetime.now()
        deadline = now + _MIN_VALIDITY
        beacon._fetch()
        exp = beacon._expiration()
        if deadline < exp:
            return beacon._token
        if now > start + _MAX_RETRY_TIME:
            break
        time.sleep(_RETRY_SLEEP_SECS)
    pytest.fail("unable to fetch token within time limit")


class TestSigstoreSigning:
    @pytest.mark.integration
    def test_sign_and_verify(
        self, sigstore_oidc_beacon_token, sample_model_folder, tmp_path
    ):
        sc = signing.Config()
        sc.use_sigstore_signer(
            use_staging=True, identity_token=sigstore_oidc_beacon_token
        )
        signature_path = tmp_path / "model.sig"
        sc.sign(sample_model_folder, signature_path)

        expected_identity = "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main"
        expected_oidc_issuer = "https://token.actions.githubusercontent.com"
        verifying.Config().use_sigstore_verifier(
            identity=expected_identity,
            oidc_issuer=expected_oidc_issuer,
            use_staging=True,
        ).verify(sample_model_folder, signature_path)

        assert get_signed_files(signature_path) == [
            "d0/f00",
            "d0/f01",
            "d0/f02",
            "d1/f10",
            "d1/f11",
            "d1/f12",
            "f0",
            "f1",
            "f2",
            "f3",
        ]
        check_ignore_paths(signature_path, True, [])
        assert get_model_name(signature_path) == os.path.basename(
            sample_model_folder
        )


class TestKeySigning:
    def test_sign_and_verify(self, base_path, populate_tmpdir):
        os.chdir(base_path)

        model_path = populate_tmpdir
        ignore_paths = []
        ignore_git_paths = False
        signature = Path(model_path / "model.sig")
        private_key = Path(TESTDATA / "keys/certificate/signing-key.pem")
        password = None

        signing.Config().use_elliptic_key_signer(
            private_key=private_key, password=password
        ).set_hashing_config(
            hashing.Config().set_ignored_paths(
                paths=list(ignore_paths) + [signature],
                ignore_git_paths=ignore_git_paths,
            )
        ).sign(model_path, signature)

        public_key = Path(TESTDATA / "keys/certificate/signing-key-pub.pem")

        verifying.Config().use_elliptic_key_verifier(
            public_key=public_key
        ).set_hashing_config(
            hashing.Config().set_ignored_paths(
                paths=list(ignore_paths) + [signature],
                ignore_git_paths=ignore_git_paths,
            )
        ).verify(model_path, signature)

        assert get_signed_files(signature) == [
            ".gitignore",
            "signme-1",
            "signme-2",
        ]
        check_ignore_paths(signature, ignore_git_paths, ["model.sig"])
        assert get_model_name(signature) == os.path.basename(model_path)

        # Ignore git paths and other files now
        ignore_paths = [Path(model_path / "ignored")]
        ignore_git_paths = True

        signing.Config().use_elliptic_key_signer(
            private_key=private_key, password=password
        ).set_hashing_config(
            hashing.Config().set_ignored_paths(
                paths=list(ignore_paths) + [signature],
                ignore_git_paths=ignore_git_paths,
            )
        ).sign(model_path, signature)

        assert get_signed_files(signature) == ["signme-1", "signme-2"]
        check_ignore_paths(
            signature, ignore_git_paths, ["model.sig", "ignored"]
        )
        assert get_model_name(signature) == os.path.basename(model_path)


class TestCertificateSigning:
    def test_sign_and_verify(self, base_path, populate_tmpdir):
        os.chdir(base_path)

        model_path = populate_tmpdir
        ignore_paths = []
        ignore_git_paths = False
        signature = Path(model_path / "model.sig")
        private_key = Path(TESTDATA / "keys/certificate/signing-key.pem")
        signing_certificate = Path(
            TESTDATA / "keys/certificate/signing-key-cert.pem"
        )
        certificate_chain = [
            Path(TESTDATA / "keys/certificate/int-ca-cert.pem")
        ]
        log_fingerprints = False

        signing.Config().use_certificate_signer(
            private_key=private_key,
            signing_certificate=signing_certificate,
            certificate_chain=certificate_chain,
        ).set_hashing_config(
            hashing.Config().set_ignored_paths(
                paths=list(ignore_paths) + [signature],
                ignore_git_paths=ignore_git_paths,
            )
        ).sign(model_path, signature)

        certificate_chain = [Path(TESTDATA / "keys/certificate/ca-cert.pem")]

        verifying.Config().use_certificate_verifier(
            certificate_chain=certificate_chain,
            log_fingerprints=log_fingerprints,
        ).set_hashing_config(
            hashing.Config().set_ignored_paths(
                paths=list(ignore_paths) + [signature],
                ignore_git_paths=ignore_git_paths,
            )
        ).verify(model_path, signature)

        assert get_signed_files(signature) == [
            ".gitignore",
            "signme-1",
            "signme-2",
        ]
        check_ignore_paths(signature, ignore_git_paths, ["model.sig"])
        assert get_model_name(signature) == os.path.basename(model_path)

        # Ignore git paths now
        ignore_paths = [Path(model_path / "ignored")]
        ignore_git_paths = True

        signing.Config().use_certificate_signer(
            private_key=private_key,
            signing_certificate=signing_certificate,
            certificate_chain=certificate_chain,
        ).set_hashing_config(
            hashing.Config().set_ignored_paths(
                paths=list(ignore_paths) + [signature],
                ignore_git_paths=ignore_git_paths,
            )
        ).sign(model_path, signature)

        assert get_signed_files(signature) == ["signme-1", "signme-2"]
        check_ignore_paths(
            signature, ignore_git_paths, ["model.sig", "ignored"]
        )
        assert get_model_name(signature) == os.path.basename(model_path)

    def test_sign_and_verify_sharded(self, base_path, populate_tmpdir):
        os.chdir(base_path)

        model_path = populate_tmpdir
        ignore_paths = []
        ignore_git_paths = False
        signature = Path(model_path / "model.sig")
        private_key = Path(TESTDATA / "keys/certificate/signing-key.pem")
        signing_certificate = Path(
            TESTDATA / "keys/certificate/signing-key-cert.pem"
        )
        certificate_chain = [
            Path(TESTDATA / "keys/certificate/int-ca-cert.pem")
        ]
        log_fingerprints = False

        signing.Config().use_certificate_signer(
            private_key=private_key,
            signing_certificate=signing_certificate,
            certificate_chain=certificate_chain,
        ).set_hashing_config(
            hashing.Config()
            .set_ignored_paths(
                paths=list(ignore_paths) + [signature],
                ignore_git_paths=ignore_git_paths,
            )
            .use_shard_serialization()
        ).sign(model_path, signature)

        certificate_chain = [Path(TESTDATA / "keys/certificate/ca-cert.pem")]

        verifying.Config().use_certificate_verifier(
            certificate_chain=certificate_chain,
            log_fingerprints=log_fingerprints,
        ).set_hashing_config(
            hashing.Config().set_ignored_paths(
                paths=list(ignore_paths) + [signature],
                ignore_git_paths=ignore_git_paths,
            )
        )
        # .verify(model_path, signature)

        assert get_signed_files(signature) == [
            ".gitignore:0:4",
            "signme-1:0:8",
            "signme-2:0:8",
        ]
        check_ignore_paths(signature, ignore_git_paths, ["model.sig"])
        assert get_model_name(signature) == os.path.basename(model_path)

        # Ignore git paths now
        ignore_paths = [Path(model_path / "ignored")]
        ignore_git_paths = True

        signing.Config().use_certificate_signer(
            private_key=private_key,
            signing_certificate=signing_certificate,
            certificate_chain=certificate_chain,
        ).set_hashing_config(
            hashing.Config()
            .set_ignored_paths(
                paths=list(ignore_paths) + [signature],
                ignore_git_paths=ignore_git_paths,
            )
            .use_shard_serialization()
        ).sign(model_path, signature)

        assert get_signed_files(signature) == ["signme-1:0:8", "signme-2:0:8"]
        check_ignore_paths(
            signature, ignore_git_paths, ["model.sig", "ignored"]
        )
        assert get_model_name(signature) == os.path.basename(model_path)


class TestMLDSASigning:
    """Integration tests for ML-DSA signing and verification."""

    def test_sign_and_verify_basic(self, base_path, populate_tmpdir):
        """Test basic ML-DSA signing and verification without password."""
        os.chdir(base_path)

        model_path = populate_tmpdir
        ignore_paths = []
        ignore_git_paths = False
        signature = Path(model_path / "model.sig")

        # Generate temporary ML-DSA key pair for testing
        from dilithium_py.ml_dsa import ML_DSA_65
        ml_dsa = ML_DSA_65

        with TemporaryDirectory() as tmpdir:
            private_key = Path(tmpdir) / "test.priv"
            public_key = Path(tmpdir) / "test.pub"

            # Generate key pair
            pk, sk = ml_dsa.keygen()
            private_key.write_bytes(sk)
            public_key.write_bytes(pk)

            # Sign the model
            signing.Config().use_ml_dsa_signer(
                private_key=private_key,
                variant="ML_DSA_65"
            ).set_hashing_config(
                hashing.Config().set_ignored_paths(
                    paths=list(ignore_paths) + [signature],
                    ignore_git_paths=ignore_git_paths,
                )
            ).sign(model_path, signature)

            # Verify the signature
            verifying.Config().use_ml_dsa_verifier(
                    public_key=public_key,
                    variant="ML_DSA_65"
                ).set_hashing_config(
                hashing.Config().set_ignored_paths(
                    paths=list(ignore_paths) + [signature],
                    ignore_git_paths=ignore_git_paths,
                )
            ).verify(model_path, signature)

            assert get_signed_files(signature) == [
                ".gitignore",
                "signme-1",
                "signme-2",
            ]
            check_ignore_paths(signature, ignore_git_paths, ["model.sig"])
            assert get_model_name(signature) == os.path.basename(model_path)

    def test_sign_and_verify_with_password(self, base_path, populate_tmpdir):
        """Test ML-DSA signing with encrypted private key."""
        os.chdir(base_path)

        model_path = populate_tmpdir
        signature = Path(model_path / "model.sig")
        test_password = "test_secure_password_123"

        # Generate temporary ML-DSA key pair
        from dilithium_py.ml_dsa import ML_DSA_65
        from model_signing._signing.sign_ml_dsa import encrypt_private_key

        ml_dsa = ML_DSA_65

        with TemporaryDirectory() as tmpdir:
            private_key = Path(tmpdir) / "test.priv"
            public_key = Path(tmpdir) / "test.pub"
            encrypted_key = Path(tmpdir) / "test_encrypted.priv"

            # Generate and encrypt key pair
            pk, sk = ml_dsa.keygen()
            private_key.write_bytes(sk)
            public_key.write_bytes(pk)

            # Encrypt the private key
            encrypted_data = encrypt_private_key(sk, test_password)
            encrypted_key.write_bytes(encrypted_data)

            # Sign with encrypted key
            signing.Config().use_ml_dsa_signer(
                private_key=encrypted_key,
                variant="ML_DSA_65",
                password=test_password
            ).set_hashing_config(
                hashing.Config().set_ignored_paths(
                    paths=[signature],
                    ignore_git_paths=False,
                )
            ).sign(model_path, signature)

            # Verify the signature
            verifying.Config().use_ml_dsa_verifier(
                    public_key=public_key,
                    variant="ML_DSA_65"
                ).set_hashing_config(
                hashing.Config().set_ignored_paths(
                    paths=[signature],
                    ignore_git_paths=False,
                )
            ).verify(model_path, signature)

            assert get_signed_files(signature) == [
                ".gitignore",
                "signme-1",
                "signme-2",
            ]

    def test_encrypted_key_wrong_password(self, base_path, populate_tmpdir):
        """Test that wrong password raises appropriate error."""
        os.chdir(base_path)

        model_path = populate_tmpdir
        signature = Path(model_path / "model.sig")
        correct_password = "correct_password"
        wrong_password = "wrong_password"

        from dilithium_py.ml_dsa import ML_DSA_44
        from model_signing._signing.sign_ml_dsa import encrypt_private_key

        ml_dsa = ML_DSA_44

        with TemporaryDirectory() as tmpdir:
            private_key = Path(tmpdir) / "test.priv"
            encrypted_key = Path(tmpdir) / "test_encrypted.priv"

            # Generate and encrypt key
            pk, sk = ml_dsa.keygen()
            private_key.write_bytes(sk)
            encrypted_data = encrypt_private_key(sk, correct_password)
            encrypted_key.write_bytes(encrypted_data)

            # Try to sign with wrong password - should raise ValueError
            with pytest.raises(ValueError, match="Failed to decrypt key"):
                signing.Config().use_ml_dsa_signer(
                    private_key=encrypted_key,
                    variant="ML_DSA_44",
                    password=wrong_password
                ).sign(model_path, signature)

    def test_encrypted_key_no_password_provided(self, base_path, populate_tmpdir):
        """Test that encrypted key without password raises error."""
        os.chdir(base_path)

        model_path = populate_tmpdir
        signature = Path(model_path / "model.sig")
        password = "test_password"

        from dilithium_py.ml_dsa import ML_DSA_87
        from model_signing._signing.sign_ml_dsa import encrypt_private_key

        ml_dsa = ML_DSA_87

        with TemporaryDirectory() as tmpdir:
            encrypted_key = Path(tmpdir) / "test_encrypted.priv"

            # Generate and encrypt key
            pk, sk = ml_dsa.keygen()
            encrypted_data = encrypt_private_key(sk, password)
            encrypted_key.write_bytes(encrypted_data)

            # Try to sign without password - should raise ValueError
            with pytest.raises(ValueError, match="Private key is encrypted but no password provided"):
                signing.Config().use_ml_dsa_signer(
                    private_key=encrypted_key,
                    variant="ML_DSA_87",
                    password=None
                ).sign(model_path, signature)

    def test_raw_key_password_provided(self, base_path, populate_tmpdir):
        """Test that providing password for raw key raises error."""
        os.chdir(base_path)

        model_path = populate_tmpdir
        signature = Path(model_path / "model.sig")

        from dilithium_py.ml_dsa import ML_DSA_65

        ml_dsa = ML_DSA_65

        with TemporaryDirectory() as tmpdir:
            private_key = Path(tmpdir) / "test.priv"

            # Generate raw key
            pk, sk = ml_dsa.keygen()
            private_key.write_bytes(sk)

            # Try to sign with password but raw key - should raise ValueError
            with pytest.raises(ValueError, match="Password provided but private key is not encrypted"):
                signing.Config().use_ml_dsa_signer(
                    private_key=private_key,
                    variant="ML_DSA_65",
                    password="some_password"
                ).sign(model_path, signature)

    def test_all_variants(self, base_path, populate_tmpdir):
        """Test all three ML-DSA variants (44, 65, 87)."""
        os.chdir(base_path)

        model_path = populate_tmpdir

        from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87

        variants = [
            ("ML_DSA_44", ML_DSA_44, 2560),
            ("ML_DSA_65", ML_DSA_65, 4032),
            ("ML_DSA_87", ML_DSA_87, 4896),
        ]

        for variant_name, ml_dsa, expected_size in variants:
            with TemporaryDirectory() as tmpdir:
                signature = Path(model_path / f"model_{variant_name}.sig")
                private_key = Path(tmpdir) / "test.priv"
                public_key = Path(tmpdir) / "test.pub"

                # Generate key pair
                pk, sk = ml_dsa.keygen()
                private_key.write_bytes(sk)
                public_key.write_bytes(pk)

                # Verify key size
                assert len(sk) == expected_size, f"Expected {expected_size} bytes for {variant_name}"

                # Sign and verify
                signing.Config().use_ml_dsa_signer(
                    private_key=private_key,
                    variant=variant_name
                ).set_hashing_config(
                    hashing.Config().set_ignored_paths(paths=[signature])
                ).sign(model_path, signature)

                verifying.Config().use_ml_dsa_verifier(
                    public_key=public_key,
                    variant=variant_name
                ).set_hashing_config(
                    hashing.Config().set_ignored_paths(paths=[signature])
                ).verify(model_path, signature)

                # Clean up signature file
                signature.unlink()

    def test_sign_with_ignored_paths(self, base_path, populate_tmpdir):
        """Test ML-DSA signing with git paths ignored."""
        os.chdir(base_path)

        model_path = populate_tmpdir
        signature = Path(model_path / "model.sig")
        ignore_paths = [Path(model_path / "ignored")]
        ignore_git_paths = True

        from dilithium_py.ml_dsa import ML_DSA_65

        ml_dsa = ML_DSA_65

        with TemporaryDirectory() as tmpdir:
            private_key = Path(tmpdir) / "test.priv"
            public_key = Path(tmpdir) / "test.pub"

            # Generate key pair
            pk, sk = ml_dsa.keygen()
            private_key.write_bytes(sk)
            public_key.write_bytes(pk)

            # Sign with ignored paths
            signing.Config().use_ml_dsa_signer(
                private_key=private_key,
                variant="ML_DSA_65"
            ).set_hashing_config(
                hashing.Config().set_ignored_paths(
                    paths=list(ignore_paths) + [signature],
                    ignore_git_paths=ignore_git_paths,
                )
            ).sign(model_path, signature)

            # Verify
            verifying.Config().use_ml_dsa_verifier(
                    public_key=public_key,
                    variant="ML_DSA_65"
                ).set_hashing_config(
                hashing.Config().set_ignored_paths(
                    paths=list(ignore_paths) + [signature],
                    ignore_git_paths=ignore_git_paths,
                )
            ).verify(model_path, signature)

            assert get_signed_files(signature) == ["signme-1", "signme-2"]
            check_ignore_paths(signature, ignore_git_paths, ["model.sig", "ignored"])
