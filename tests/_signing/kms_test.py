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

import os
import pathlib

import pytest

import model_signing.hashing
import model_signing.signing
import model_signing.verifying
from tests.api_test import check_ignore_paths
from tests.api_test import get_model_name
from tests.api_test import get_signed_files


TESTDATA = (
    pathlib.Path(__file__).parent.parent.parent
    / "scripts"
    / "tests"
    / "keys"
    / "certificate"
)


class TestKMSSigning:
    def test_sign_and_verify_file_backend(self, base_path, populate_tmpdir):
        os.chdir(base_path)

        private_key = TESTDATA / "signing-key.pem"
        public_key = TESTDATA / "signing-key-pub.pem"
        kms_uri = f"kms://file/{private_key.absolute().as_posix()}"

        model_path = populate_tmpdir
        ignore_paths = [pathlib.Path(model_path / "ignored")]
        ignore_git_paths = False
        signature = pathlib.Path(model_path / "model.sig")

        model_signing.signing.Config().use_kms_signer(
            kms_uri=kms_uri
        ).set_hashing_config(
            model_signing.hashing.Config().set_ignored_paths(
                paths=list(ignore_paths) + [signature],
                ignore_git_paths=ignore_git_paths,
            )
        ).sign(model_path, signature)

        model_signing.verifying.Config().use_elliptic_key_verifier(
            public_key=public_key
        ).set_hashing_config(
            model_signing.hashing.Config().set_ignored_paths(
                paths=list(ignore_paths) + [signature],
                ignore_git_paths=ignore_git_paths,
            )
        ).verify(model_path, signature)

        assert get_signed_files(signature) == [
            ".gitignore",
            "signme-1",
            "signme-2",
        ]
        check_ignore_paths(
            signature, ignore_git_paths, ["ignored", "model.sig"]
        )
        assert get_model_name(signature) == os.path.basename(model_path)

    def test_kms_uri_parsing(self):
        from model_signing._signing.sign_kms import _parse_kms_uri

        provider, params = _parse_kms_uri("kms://file/path/to/key.pem")
        assert provider == "file"
        assert params["path"] == "/path/to/key.pem"

        provider, params = _parse_kms_uri("kms://aws/key-id")
        assert provider == "aws"
        assert params["key_id"] == "key-id"

        provider, params = _parse_kms_uri("kms://aws/key-id?region=us-east-1")
        assert provider == "aws"
        assert params["key_id"] == "key-id"
        assert params["region"] == "us-east-1"

        provider, params = _parse_kms_uri(
            "kms://aws/arn:aws:kms:us-east-1:123456789012:key/"
            "f26f2baa-8865-459d-a275-8fca1d15119f"
        )
        assert provider == "aws"
        expected_arn = (
            "arn:aws:kms:us-east-1:123456789012:key/"
            "f26f2baa-8865-459d-a275-8fca1d15119f"
        )
        assert params["key_id"] == expected_arn

        provider, params = _parse_kms_uri(
            "kms://gcp/project/location/keyring/key"
        )
        assert provider == "gcp"
        assert params["project_id"] == "project"
        assert params["location"] == "location"
        assert params["keyring"] == "keyring"
        assert params["key_name"] == "key"

        provider, params = _parse_kms_uri("kms://azure/vault/key")
        assert provider == "azure"
        assert params["vault_url"] == "https://vault"
        assert params["key_name"] == "key"

        provider, params = _parse_kms_uri("kms://azure/vault/key?version=1")
        assert provider == "azure"
        assert params["vault_url"] == "https://vault"
        assert params["key_name"] == "key"
        assert params["version"] == "1"

    def test_invalid_kms_uri(self):
        from model_signing._signing.sign_kms import _parse_kms_uri

        with pytest.raises(ValueError, match="Invalid KMS URI scheme"):
            _parse_kms_uri("invalid://file/path")

        with pytest.raises(ValueError, match="Unsupported KMS provider"):
            _parse_kms_uri("kms://unknown/provider")

        with pytest.raises(ValueError, match="File KMS URI must have format"):
            _parse_kms_uri("kms://file")

        with pytest.raises(ValueError, match="AWS KMS URI must be either"):
            _parse_kms_uri("kms://aws/key-id/extra")

        with pytest.raises(ValueError, match="AWS KMS ARN must have format"):
            _parse_kms_uri("kms://aws/arn:aws:kms:invalid")

        with pytest.raises(ValueError, match="GCP KMS URI must have format"):
            _parse_kms_uri("kms://gcp/project/location/keyring")

        with pytest.raises(ValueError, match="Azure KMS URI must have format"):
            _parse_kms_uri("kms://azure/vault")
