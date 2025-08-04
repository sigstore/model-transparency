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

"""Tests for the CLI."""

import os
import pathlib

import pytest

import model_signing


@pytest.fixture
def base_path() -> pathlib.Path:
    return pathlib.Path(__file__).parent


class TestVerify:
    def test_verify_key_v0_3_1(self, base_path: pathlib.Path):
        os.chdir(base_path)

        model_path = pathlib.Path("./v0.3.1-certificate")
        signature = pathlib.Path("./v0.3.1-certificate/model.sig")
        ignore_paths = []
        ignore_git_paths = False
        public_key = pathlib.Path("./keys/certificate/signing-key-pub.pem")

        model_signing.verifying.Config().use_elliptic_key_verifier(
            public_key=public_key
        ).set_hashing_config(
            model_signing.hashing.Config().set_ignored_paths(
                paths=list(ignore_paths) + [signature.name],
                ignore_git_paths=ignore_git_paths,
            )
        ).verify(model_path, signature)

    def test_verify_certificate_v0_3_1(self, base_path: pathlib.Path):
        os.chdir(base_path)

        model_path = pathlib.Path("./v0.3.1-certificate")
        signature = pathlib.Path("./v0.3.1-certificate/model.sig")
        ignore_paths = []
        ignore_git_paths = False
        log_fingerprints = False
        certificate_chain = [pathlib.Path("./keys/certificate/ca-cert.pem")]

        model_signing.verifying.Config().use_certificate_verifier(
            certificate_chain=certificate_chain,
            log_fingerprints=log_fingerprints,
        ).set_hashing_config(
            model_signing.hashing.Config().set_ignored_paths(
                paths=list(ignore_paths) + [signature.name],
                ignore_git_paths=ignore_git_paths,
            )
        ).verify(model_path, signature)

    def test_verify_sigstore_v0_3_1(self, base_path: pathlib.Path):
        os.chdir(base_path)

        model_path = pathlib.Path("./v0.3.1-sigstore")
        signature = pathlib.Path("./v0.3.1-sigstore/model.sig")
        ignore_paths = []
        ignore_git_paths = False
        identity = "stefanb@us.ibm.com"
        identity_provider = "https://sigstore.verify.ibm.com/oauth2"
        use_staging = False

        model_signing.verifying.Config().use_sigstore_verifier(
            identity=identity,
            oidc_issuer=identity_provider,
            use_staging=use_staging,
        ).set_hashing_config(
            model_signing.hashing.Config().set_ignored_paths(
                paths=list(ignore_paths) + [signature.name],
                ignore_git_paths=ignore_git_paths,
            )
        ).verify(model_path, signature)

    def test_verify_key_v1_0_0(self, base_path: pathlib.Path):
        os.chdir(base_path)

        model_path = pathlib.Path("./v1.0.0-certificate")
        signature = pathlib.Path("./v1.0.0-certificate/model.sig")
        ignore_paths = []
        ignore_git_paths = False
        public_key = pathlib.Path("./keys/certificate/signing-key-pub.pem")

        model_signing.verifying.Config().use_elliptic_key_verifier(
            public_key=public_key
        ).set_hashing_config(
            model_signing.hashing.Config().set_ignored_paths(
                paths=list(ignore_paths) + [signature.name],
                ignore_git_paths=ignore_git_paths,
            )
        ).verify(model_path, signature)

    def test_verify_certificate_v1_0_0(self, base_path: pathlib.Path):
        os.chdir(base_path)

        model_path = pathlib.Path("./v1.0.0-certificate")
        signature = pathlib.Path("./v1.0.0-certificate/model.sig")
        ignore_paths = []
        ignore_git_paths = False
        certificate_chain = [pathlib.Path("./keys/certificate/ca-cert.pem")]
        log_fingerprints = False

        model_signing.verifying.Config().use_certificate_verifier(
            certificate_chain=certificate_chain,
            log_fingerprints=log_fingerprints,
        ).set_hashing_config(
            model_signing.hashing.Config().set_ignored_paths(
                paths=list(ignore_paths) + [signature.name],
                ignore_git_paths=ignore_git_paths,
            )
        ).verify(model_path, signature)

    def test_verify_sigstore_v1_0_0(self, base_path: pathlib.Path):
        os.chdir(base_path)

        model_path = pathlib.Path("./v1.0.0-sigstore")
        signature = pathlib.Path("./v1.0.0-sigstore/model.sig")
        ignore_paths = []
        ignore_git_paths = False
        identity = "stefanb@us.ibm.com"
        identity_provider = "https://sigstore.verify.ibm.com/oauth2"
        use_staging = False

        model_signing.verifying.Config().use_sigstore_verifier(
            identity=identity,
            oidc_issuer=identity_provider,
            use_staging=use_staging,
        ).set_hashing_config(
            model_signing.hashing.Config().set_ignored_paths(
                paths=list(ignore_paths) + [signature.name],
                ignore_git_paths=ignore_git_paths,
            )
        ).verify(model_path, signature)
