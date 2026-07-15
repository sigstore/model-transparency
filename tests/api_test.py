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
import urllib.request

import pytest

from model_signing import hashing
from model_signing import manifest
from model_signing import signing
from model_signing import verifying
from model_signing._hashing import hashing as _hashing
from model_signing._hashing import memory
from model_signing._signing import sign_ec_key
from model_signing._signing import signing as _signing


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
        url = "https://storage.googleapis.com/sigstore-conformance-testing-token/untrusted-testing-token.txt"
        with urllib.request.urlopen(url) as response:
            self._token = response.read().decode("utf-8").rstrip()

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

        expected_identity = "untrusted-sa@sigstore-conformance.iam.gserviceaccount.com"
        expected_oidc_issuer = "https://accounts.google.com"
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

    @pytest.mark.integration
    def test_sign_and_verify_with_custom_trust_config(
        self, sigstore_oidc_beacon_token, sample_model_folder, tmp_path
    ):
        trust_config_path = (
            Path(__file__).parent
            / "_signing"
            / "testdata"
            / "custom_trust_config.json"
        )

        sc = signing.Config()
        sc.use_sigstore_signer(
            use_staging=False,
            identity_token=sigstore_oidc_beacon_token,
            trust_config=trust_config_path,
        )
        signature_path = tmp_path / "model.sig"
        sc.sign(sample_model_folder, signature_path)

        expected_identity = "untrusted-sa@sigstore-conformance.iam.gserviceaccount.com"
        expected_oidc_issuer = "https://accounts.google.com"
        verifying.Config().use_sigstore_verifier(
            identity=expected_identity,
            oidc_issuer=expected_oidc_issuer,
            use_staging=False,
            trust_config=trust_config_path,
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


class TestIgnoreUnsignedFilesTraversal:
    def _sha256(self, path: Path) -> _hashing.Digest:
        hasher = memory.SHA256()
        hasher.update(path.read_bytes())
        digest = hasher.compute()
        return _hashing.Digest("sha256", digest.digest_value)

    def _sign_manifest(
        self, mani: manifest.Manifest, private_key: Path, out: Path
    ) -> None:
        signer = sign_ec_key.Signer(private_key)
        signature = signer.sign(_signing.Payload(mani))
        signature.write(out)

    def test_verify_rejects_path_outside_model(self, tmp_path):
        model = tmp_path / "model"
        model.mkdir()
        (model / "weights.bin").write_bytes(b"legit weights")
        secret = tmp_path / "secret.txt"
        secret.write_bytes(b"outside the model root")

        items = [
            manifest.FileManifestItem(
                path=Path("weights.bin"),
                digest=self._sha256(model / "weights.bin"),
            ),
            manifest.FileManifestItem(
                path=Path("../secret.txt"),
                digest=self._sha256(secret),
            ),
        ]
        serialization = manifest._FileSerialization("sha256")
        mani = manifest.Manifest("model", items, serialization)

        private_key = Path(TESTDATA / "keys/certificate/signing-key.pem")
        public_key = Path(TESTDATA / "keys/certificate/signing-key-pub.pem")
        signature = tmp_path / "model.sig"
        self._sign_manifest(mani, private_key, signature)

        with pytest.raises(ValueError, match="outside the model directory"):
            verifying.Config().use_elliptic_key_verifier(
                public_key=public_key
            ).set_ignore_unsigned_files(True).verify(model, signature)

    def test_verify_accepts_in_model_paths(self, tmp_path):
        model = tmp_path / "model"
        model.mkdir()
        (model / "weights.bin").write_bytes(b"legit weights")

        private_key = Path(TESTDATA / "keys/certificate/signing-key.pem")
        public_key = Path(TESTDATA / "keys/certificate/signing-key-pub.pem")
        signature = tmp_path / "model.sig"

        signing.Config().use_elliptic_key_signer(
            private_key=private_key
        ).sign(model, signature)

        verifying.Config().use_elliptic_key_verifier(
            public_key=public_key
        ).set_ignore_unsigned_files(True).verify(model, signature)
