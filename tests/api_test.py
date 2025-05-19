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


@pytest.fixture
def base_path() -> Path:
    return Path(__file__).parent


@pytest.fixture
def populate_tmpdir(tmp_path: Path) -> Path:
    Path(tmp_path / "signme-1").write_text("signme-1")
    Path(tmp_path / "signme-2").write_text("signme-2")
    return tmp_path


def get_signed_files(modelsig: Path) -> list[str]:
    with open(modelsig, "r") as file:
        signature = json.load(file)
    payload = json.loads(b64decode(signature["dsseEnvelope"]["payload"]))
    return [entry["name"] for entry in payload["predicate"]["resources"]]


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

        assert ["signme-1", "signme-2"] == get_signed_files(signature_path)


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

        assert ["signme-1", "signme-2"] == get_signed_files(signature)


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

        assert ["signme-1", "signme-2"] == get_signed_files(signature)
