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

import pytest


class TestKMSSigning:
    def test_kms_uri_parsing(self):
        from model_signing._signing.sign_kms import _parse_kms_uri

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

    def test_invalid_kms_uri(self):
        from model_signing._signing.sign_kms import _parse_kms_uri

        with pytest.raises(ValueError, match="Invalid KMS URI scheme"):
            _parse_kms_uri("invalid://aws/key")

        with pytest.raises(ValueError, match="Unsupported KMS provider"):
            _parse_kms_uri("kms://unknown/provider")

        with pytest.raises(ValueError, match="Unsupported KMS provider"):
            _parse_kms_uri("kms://gcp/project/location/keyring/key")

        with pytest.raises(ValueError, match="Unsupported KMS provider"):
            _parse_kms_uri("kms://azure/vault/key")

        with pytest.raises(ValueError, match="Unsupported KMS provider"):
            _parse_kms_uri("kms://file/path/to/key.pem")

        with pytest.raises(ValueError, match="AWS KMS URI must be either"):
            _parse_kms_uri("kms://aws/key-id/extra")

        with pytest.raises(ValueError, match="AWS KMS ARN must have format"):
            _parse_kms_uri("kms://aws/arn:aws:kms:invalid")
