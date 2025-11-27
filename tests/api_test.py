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
import hashlib
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


def _create_mock_oci_manifest_from_directory(
    model_path: Path, include_config: bool = True
) -> dict:
    """Create a mock OCI manifest from a local directory.

    This simulates what `skopeo inspect --raw` would return for an ORAS-uploaded
    model where each file is a separate layer with annotations.
    """
    layers = []

    for file_path in sorted(model_path.rglob("*")):
        if file_path.is_file():
            relative_path = file_path.relative_to(model_path)

            with open(file_path, "rb") as f:
                file_content = f.read()
            digest_hex = hashlib.sha256(file_content).hexdigest()
            digest = f"sha256:{digest_hex}"

            media_type = "application/octet-stream"
            if relative_path.suffix == ".json":
                media_type = "application/json"
            elif relative_path.suffix in [".txt", ".md"]:
                media_type = "text/plain"
            elif relative_path.suffix == ".md":
                media_type = "text/markdown"

            layer = {
                "mediaType": media_type,
                "digest": digest,
                "size": len(file_content),
                "annotations": {
                    "org.opencontainers.image.title": str(relative_path)
                },
            }
            layers.append(layer)

    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": layers,
    }

    if include_config:
        config_content = b'{"architecture":"amd64","os":"linux"}'
        config_digest_hex = hashlib.sha256(config_content).hexdigest()
        manifest["config"] = {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": f"sha256:{config_digest_hex}",
            "size": len(config_content),
        }

    return manifest


class TestOCIManifestSigning:
    """Tests for signing and verifying with OCI manifests."""

    def test_sign_oci_manifest_verify_oci_manifest(
        self, base_path, populate_tmpdir
    ):
        """Test signing from OCI manifest and verifying against OCI manifest."""
        os.chdir(base_path)

        model_path = populate_tmpdir
        signature = Path(model_path / "model.sig")
        private_key = Path(TESTDATA / "keys/certificate/signing-key.pem")
        public_key = Path(TESTDATA / "keys/certificate/signing-key-pub.pem")

        oci_manifest = _create_mock_oci_manifest_from_directory(model_path)

        model_manifest = hashing.create_manifest_from_oci_layers(oci_manifest)
        signing.Config().use_elliptic_key_signer(
            private_key=private_key, password=None
        ).sign_from_manifest(model_manifest, signature)

        verifying.Config().use_elliptic_key_verifier(
            public_key=public_key
        ).verify_from_oci_manifest(oci_manifest, signature)

    def test_sign_oci_manifest_verify_local_files(
        self, base_path, populate_tmpdir
    ):
        """Test signing from OCI manifest and verifying against local files."""
        os.chdir(base_path)

        model_path = populate_tmpdir
        signature = Path(model_path / "model.sig")
        private_key = Path(TESTDATA / "keys/certificate/signing-key.pem")
        public_key = Path(TESTDATA / "keys/certificate/signing-key-pub.pem")

        oci_manifest = _create_mock_oci_manifest_from_directory(
            model_path, include_config=False
        )

        model_manifest = hashing.create_manifest_from_oci_layers(
            oci_manifest, include_config=False
        )
        signing.Config().use_elliptic_key_signer(
            private_key=private_key, password=None
        ).sign_from_manifest(model_manifest, signature)

        verifying.Config().use_elliptic_key_verifier(
            public_key=public_key
        ).set_hashing_config(
            hashing.Config().set_ignored_paths(
                paths=[signature], ignore_git_paths=False
            )
        ).verify(model_path, signature)

    def test_sign_local_files_verify_oci_manifest(
        self, base_path, populate_tmpdir
    ):
        """Test signing from local files and verifying against OCI manifest."""
        os.chdir(base_path)

        model_path = populate_tmpdir
        signature = Path(model_path / "model.sig")
        private_key = Path(TESTDATA / "keys/certificate/signing-key.pem")
        public_key = Path(TESTDATA / "keys/certificate/signing-key-pub.pem")

        signing.Config().use_elliptic_key_signer(
            private_key=private_key, password=None
        ).set_hashing_config(
            hashing.Config().set_ignored_paths(
                paths=[signature], ignore_git_paths=False
            )
        ).sign(model_path, signature)

        oci_manifest = _create_mock_oci_manifest_from_directory(model_path)

        verifier = verifying.Config().use_elliptic_key_verifier(
            public_key=public_key
        )

        try:
            verifier.verify_from_oci_manifest(
                oci_manifest, signature, include_config=False
            )
        except ValueError as e:
            error_msg = str(e).lower()
            assert (
                "mismatch" in error_msg
                or "manifest" in error_msg
                or "digest" in error_msg
                or "signature" in error_msg
            )

    def test_create_manifest_from_oci_layers_missing_layers(self):
        """Test that missing 'layers' field raises ValueError."""
        invalid_manifest = {"schemaVersion": 2}
        with pytest.raises(ValueError, match="missing 'layers' field"):
            hashing.create_manifest_from_oci_layers(invalid_manifest)

    def test_create_manifest_from_oci_layers_empty_layers(self):
        """Test that empty layers array raises ValueError."""
        manifest = {"layers": []}
        with pytest.raises(ValueError, match="No digests found"):
            hashing.create_manifest_from_oci_layers(manifest)

    def test_verify_oci_manifest_mismatch_digest(
        self, base_path, populate_tmpdir
    ):
        """Test verification fails when OCI manifest digests don't match."""
        os.chdir(base_path)

        model_path = populate_tmpdir
        signature = Path(model_path / "model.sig")
        private_key = Path(TESTDATA / "keys/certificate/signing-key.pem")
        public_key = Path(TESTDATA / "keys/certificate/signing-key-pub.pem")

        oci_manifest1 = _create_mock_oci_manifest_from_directory(
            model_path, include_config=False
        )
        model_manifest = hashing.create_manifest_from_oci_layers(
            oci_manifest1, include_config=False
        )
        signing.Config().use_elliptic_key_signer(
            private_key=private_key, password=None
        ).sign_from_manifest(model_manifest, signature)

        oci_manifest2 = json.loads(json.dumps(oci_manifest1))  # Deep copy
        oci_manifest2["layers"][0]["digest"] = (
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        )

        with pytest.raises(ValueError, match="Signature mismatch"):
            verifying.Config().use_elliptic_key_verifier(
                public_key=public_key
            ).verify_from_oci_manifest(
                oci_manifest2, signature, include_config=False
            )

    def test_verify_local_files_mismatch_oci_signature(
        self, base_path, populate_tmpdir
    ):
        """Test verification fails when local files don't match OCI."""
        os.chdir(base_path)

        model_path = populate_tmpdir
        signature = Path(model_path / "model.sig")
        private_key = Path(TESTDATA / "keys/certificate/signing-key.pem")
        public_key = Path(TESTDATA / "keys/certificate/signing-key-pub.pem")

        oci_manifest = _create_mock_oci_manifest_from_directory(
            model_path, include_config=False
        )
        model_manifest = hashing.create_manifest_from_oci_layers(
            oci_manifest, include_config=False
        )
        signing.Config().use_elliptic_key_signer(
            private_key=private_key, password=None
        ).sign_from_manifest(model_manifest, signature)

        (model_path / "signme-1").write_text("modified content")

        with pytest.raises(
            ValueError, match="Signature mismatch|mismatch|Hash mismatch"
        ):
            verifying.Config().use_elliptic_key_verifier(
                public_key=public_key
            ).set_hashing_config(
                hashing.Config().set_ignored_paths(
                    paths=[signature], ignore_git_paths=False
                )
            ).verify(model_path, signature)

    def test_sign_oci_manifest_with_certificate(
        self, base_path, populate_tmpdir
    ):
        """Test signing OCI manifest with certificate method."""
        os.chdir(base_path)

        model_path = populate_tmpdir
        signature = Path(model_path / "model.sig")
        private_key = Path(TESTDATA / "keys/certificate/signing-key.pem")
        signing_certificate = Path(
            TESTDATA / "keys/certificate/signing-key-cert.pem"
        )
        certificate_chain = [
            Path(TESTDATA / "keys/certificate/int-ca-cert.pem")
        ]

        oci_manifest = _create_mock_oci_manifest_from_directory(
            model_path, include_config=False
        )
        model_manifest = hashing.create_manifest_from_oci_layers(
            oci_manifest, include_config=False
        )

        signing.Config().use_certificate_signer(
            private_key=private_key,
            signing_certificate=signing_certificate,
            certificate_chain=certificate_chain,
        ).sign_from_manifest(model_manifest, signature)

        certificate_chain = [Path(TESTDATA / "keys/certificate/ca-cert.pem")]
        verifying.Config().use_certificate_verifier(
            certificate_chain=certificate_chain
        ).verify_from_oci_manifest(
            oci_manifest, signature, include_config=False
        )
