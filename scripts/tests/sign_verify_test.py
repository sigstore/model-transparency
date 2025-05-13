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

"""Tests for the top level API."""

from base64 import b64decode
import json
import os
from pathlib import Path

import pytest

import model_signing


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


class TestKeySigning:
    def test_sign_and_verify(self, base_path, populate_tmpdir):
        os.chdir(base_path)

        model_path = populate_tmpdir
        ignore_paths = []
        ignore_git_paths = False
        signature = Path(model_path / "model.sig")
        private_key = Path("./keys/certificate/signing-key.pem")
        password = None

        model_signing.signing.Config().use_elliptic_key_signer(
            private_key=private_key, password=password
        ).set_hashing_config(
            model_signing.hashing.Config().set_ignored_paths(
                paths=list(ignore_paths) + [signature],
                ignore_git_paths=ignore_git_paths,
            )
        ).sign(model_path, signature)

        public_key = Path("./keys/certificate/signing-key-pub.pem")

        model_signing.verifying.Config().use_elliptic_key_verifier(
            public_key=public_key
        ).set_hashing_config(
            model_signing.hashing.Config().set_ignored_paths(
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
        private_key = Path("./keys/certificate/signing-key.pem")
        signing_certificate = Path("./keys/certificate/signing-key-cert.pem")
        certificate_chain = [Path("./keys/certificate/int-ca-cert.pem")]
        log_fingerprints = False

        model_signing.signing.Config().use_certificate_signer(
            private_key=private_key,
            signing_certificate=signing_certificate,
            certificate_chain=certificate_chain,
        ).set_hashing_config(
            model_signing.hashing.Config().set_ignored_paths(
                paths=list(ignore_paths) + [signature],
                ignore_git_paths=ignore_git_paths,
            )
        ).sign(model_path, signature)

        certificate_chain = [Path("./keys/certificate/ca-cert.pem")]

        model_signing.verifying.Config().use_certificate_verifier(
            certificate_chain=certificate_chain,
            log_fingerprints=log_fingerprints,
        ).set_hashing_config(
            model_signing.hashing.Config().set_ignored_paths(
                paths=list(ignore_paths) + [signature],
                ignore_git_paths=ignore_git_paths,
            )
        ).verify(model_path, signature)

        assert ["signme-1", "signme-2"] == get_signed_files(signature)
