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

"""Tests for signing and verification with Sigstore."""

import json
import pathlib
import sys
from unittest import mock

import pytest

from model_signing._hashing import io
from model_signing._hashing import memory
from model_signing._serialization import file
from model_signing._signing import sign_sigstore as sigstore
from model_signing._signing import signing


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


class MockedSigstoreBundle:
    """Mocked sigstore bundle that just records the signed payload."""

    def __init__(self, data):
        self._data = data

    def to_json(self) -> str:
        """Convert the bundle to json for saving."""
        return self._data._contents.decode("utf-8")

    @classmethod
    def from_json(cls, data) -> Self:
        """Reads a bundle from json."""
        return cls(json.loads(data))


def _mocked_verify_dsse(
    bundle, policy, json_type=signing._IN_TOTO_JSON_PAYLOAD_TYPE
):
    """Mocked replacement for `sigstore.Verifier.verify_dsse`."""
    return json_type, json.dumps(bundle._data)


@pytest.fixture
def mocked_oidc_provider():
    with mock.patch.multiple(
        sigstore.sigstore_oidc,
        detect_credential=mock.DEFAULT,
        IdentityToken=mock.DEFAULT,
        Issuer=mock.DEFAULT,
        autospec=True,
    ) as mocked_objects:
        mocked_detect_credential = mocked_objects["detect_credential"]
        mocked_detect_credential.return_value = "fake_token"

        # return whatever raw_token was passed in
        mocked_identity_token = mocked_objects["IdentityToken"]
        mocked_identity_token.side_effect = lambda token, client_id: token

        mocked_issuer = mocked_objects["Issuer"]
        mocked_issuer.return_value.identity_token.return_value = "fake_token"

        yield mocked_objects


@pytest.fixture
def mocked_oidc_provider_no_ambient():
    with mock.patch.multiple(
        sigstore.sigstore_oidc,
        detect_credential=mock.DEFAULT,
        IdentityToken=mock.DEFAULT,
        Issuer=mock.DEFAULT,
        autospec=True,
    ) as mocked_objects:
        mocked_detect_credential = mocked_objects["detect_credential"]
        mocked_detect_credential.return_value = ""

        mocked_identity_token = mocked_objects["IdentityToken"]
        mocked_identity_token.return_value = "fake_token"

        mocked_issuer = mocked_objects["Issuer"]
        mocked_issuer.return_value.identity_token.return_value = "fake_token"

        yield mocked_objects


@pytest.fixture
def mocked_sigstore_models():
    with mock.patch.multiple(
        sigstore.sigstore_models,
        Bundle=mock.DEFAULT,
        ClientTrustConfig=mock.DEFAULT,
        autospec=True,
    ) as mocked_objects:
        mocked_bundle = mocked_objects["Bundle"]
        mocked_bundle.from_json = MockedSigstoreBundle.from_json

        mocked_config = mock.MagicMock()
        mocked_client_trust_config = mocked_objects["ClientTrustConfig"]
        mocked_client_trust_config.production.return_value = mocked_config
        mocked_client_trust_config.staging.return_value = mocked_config

        yield mocked_objects


@pytest.fixture
def mocked_sigstore_signer(mocked_sigstore_models):
    with mock.patch.multiple(
        sigstore.sigstore_signer,
        Signer=mock.DEFAULT,
        SigningContext=mock.DEFAULT,
        autospec=True,
    ) as mocked_objects:
        signer = mock.MagicMock()
        signer.sign_dsse = MockedSigstoreBundle
        signer.__enter__.return_value = signer

        mocked_signer = mocked_objects["Signer"]
        mocked_signer.return_value = signer

        mocked_context = mock.MagicMock()
        mocked_context.signer.return_value = signer

        mocked_signing_context = mocked_objects["SigningContext"]
        mocked_signing_context.from_trust_config.return_value = mocked_context

        yield mocked_objects


@pytest.fixture
def mocked_sigstore_verifier():
    with mock.patch.object(
        sigstore.sigstore_verifier, "Verifier", autospec=True
    ) as mocked_verifier:
        mocked_verifier.verify_dsse = _mocked_verify_dsse
        mocked_verifier.return_value = mocked_verifier
        yield mocked_verifier


@pytest.fixture
def mocked_sigstore_verifier_bad_payload():
    def _verify_dsse(bundle, policy):
        return _mocked_verify_dsse(bundle, policy, "not DDSE")

    with mock.patch.object(
        sigstore.sigstore_verifier, "Verifier", autospec=True
    ) as mocked_verifier:
        mocked_verifier.verify_dsse = _verify_dsse
        mocked_verifier.return_value = mocked_verifier
        yield mocked_verifier


@pytest.fixture
def mocked_sigstore(
    mocked_oidc_provider,
    mocked_sigstore_models,
    mocked_sigstore_signer,
    mocked_sigstore_verifier,
):
    """Collect all sigstore mocking fixtures in just one."""
    return True  # keep in scope


class TestSigning:
    def _file_hasher_factory(self, path: pathlib.Path) -> io.FileHasher:
        return io.SimpleFileHasher(path, memory.SHA256())

    def _shard_hasher_factory(
        self, path: pathlib.Path, start: int, end: int
    ) -> io.ShardedFileHasher:
        return io.ShardedFileHasher(path, memory.SHA256(), start=start, end=end)

    def _sign_manifest(
        self,
        manifest,
        signature_path,
        signer_type,
        use_staging=True,
        oidc_issuer=None,
    ):
        payload = signing.Payload(manifest)
        signer = signer_type(use_staging=use_staging, oidc_issuer=oidc_issuer)
        signature = signer.sign(payload)
        signature.write(signature_path)

    def _verify_dsse_signature(self, signature_path, use_staging=True):
        signature = sigstore.Signature.read(signature_path)
        verifier = sigstore.Verifier(
            identity="test", oidc_issuer="test", use_staging=use_staging
        )
        return verifier.verify(signature)

    def test_sign_verify_dsse_digests(
        self, sample_model_folder, mocked_sigstore, tmp_path
    ):
        # Serialize and sign model
        serializer = file.Serializer(
            self._file_hasher_factory, allow_symlinks=True
        )
        manifest = serializer.serialize(sample_model_folder)
        signature_path = tmp_path / "model.sig"
        self._sign_manifest(manifest, signature_path, sigstore.Signer)

        # Read signature and check against expected serialization
        expected_manifest = self._verify_dsse_signature(signature_path)
        assert expected_manifest == manifest

    def test_sign_verify_mocked_prod(
        self, sample_model_folder, mocked_sigstore, tmp_path
    ):
        # Serialize and sign model
        serializer = file.Serializer(
            self._file_hasher_factory, allow_symlinks=True
        )
        manifest = serializer.serialize(sample_model_folder)
        signature_path = tmp_path / "model.sig"
        self._sign_manifest(
            manifest, signature_path, sigstore.Signer, use_staging=False
        )

        # Read signature and check against expected serialization
        expected_manifest = self._verify_dsse_signature(
            signature_path, use_staging=False
        )
        assert expected_manifest == manifest

    def test_sign_verify_mocked_prod_oidc(
        self, sample_model_folder, mocked_sigstore, tmp_path
    ):
        # Serialize and sign model
        serializer = file.Serializer(
            self._file_hasher_factory, allow_symlinks=True
        )
        manifest = serializer.serialize(sample_model_folder)
        signature_path = tmp_path / "model.sig"
        self._sign_manifest(
            manifest,
            signature_path,
            sigstore.Signer,
            use_staging=False,
            oidc_issuer="test",
        )

        # Read signature and check against expected serialization
        expected_manifest = self._verify_dsse_signature(
            signature_path, use_staging=False
        )
        assert expected_manifest == manifest

    def test_sign_verify_mocked_ambient(
        self,
        sample_model_folder,
        mocked_oidc_provider_no_ambient,
        mocked_sigstore_signer,
        mocked_sigstore_models,
        mocked_sigstore_verifier,
        tmp_path,
    ):
        # Serialize and sign model
        serializer = file.Serializer(
            self._file_hasher_factory, allow_symlinks=True
        )
        manifest = serializer.serialize(sample_model_folder)
        signature_path = tmp_path / "model.sig"
        self._sign_manifest(manifest, signature_path, sigstore.Signer)

        # Read signature and check against expected serialization
        expected_manifest = self._verify_dsse_signature(signature_path)
        assert expected_manifest == manifest

    def test_sign_identity_token_precedence(
        self, mocked_oidc_provider, mocked_sigstore_signer
    ):
        signer = sigstore.Signer(identity_token="provided_token")
        token = signer._get_identity_token()
        assert token == "provided_token"

        signer = sigstore.Signer()
        token = signer._get_identity_token()
        assert token == "fake_token"

    def test_verify_not_into_json_payload(
        self,
        sample_model_folder,
        mocked_oidc_provider,
        mocked_sigstore_signer,
        mocked_sigstore_models,
        mocked_sigstore_verifier_bad_payload,
        tmp_path,
    ):
        serializer = file.Serializer(
            self._file_hasher_factory, allow_symlinks=True
        )
        manifest = serializer.serialize(sample_model_folder)
        signature_path = tmp_path / "model.sig"
        self._sign_manifest(manifest, signature_path, sigstore.Signer)

        with pytest.raises(ValueError, match="Expected DSSE payload"):
            self._verify_dsse_signature(signature_path)

    def test_verify_not_intoto_statement(
        self, sample_model_folder, mocked_sigstore, tmp_path
    ):
        serializer = file.Serializer(
            self._file_hasher_factory, allow_symlinks=True
        )
        manifest = serializer.serialize(sample_model_folder)
        signature_path = tmp_path / "model.sig"
        self._sign_manifest(manifest, signature_path, sigstore.Signer)

        correct_signature = signature_path.read_text(encoding="utf-8")
        json_signature = json.loads(correct_signature)
        json_signature["_type"] = "Not in-toto"
        invalid_signature = json.dumps(json_signature)
        signature_path.write_text(invalid_signature, encoding="utf-8")

        with pytest.raises(ValueError, match="Expected in-toto .* payload"):
            self._verify_dsse_signature(signature_path)

    def test_sign_with_custom_trust_config(
        self,
        sample_model_folder,
        mocked_oidc_provider,
        mocked_sigstore_signer,
        mocked_sigstore_models,
        tmp_path,
    ):
        trust_config_path = (
            pathlib.Path(__file__).parent
            / "testdata"
            / "custom_trust_config.json"
        )

        serializer = file.Serializer(
            self._file_hasher_factory, allow_symlinks=True
        )
        manifest = serializer.serialize(sample_model_folder)
        signature_path = tmp_path / "model.sig"

        mocked_client_trust_config = mocked_sigstore_models["ClientTrustConfig"]
        mocked_custom_config = mock.MagicMock()
        mocked_client_trust_config.from_json.return_value = mocked_custom_config

        signer = sigstore.Signer(
            use_staging=False, trust_config=trust_config_path
        )
        payload = signing.Payload(manifest)
        signature = signer.sign(payload)
        signature.write(signature_path)

        assert mocked_client_trust_config.from_json.called
        call_args = mocked_client_trust_config.from_json.call_args
        assert call_args is not None
        assert isinstance(call_args[0][0], str)
        trust_config_content = json.loads(call_args[0][0])
        assert trust_config_content["mediaType"] == (
            "application/vnd.dev.sigstore.clienttrustconfig.v0.1+json"
        )
        assert "signing_config" in trust_config_content
        assert "trustedRoot" in trust_config_content

    def test_verify_with_custom_trust_config(
        self,
        sample_model_folder,
        mocked_oidc_provider,
        mocked_sigstore_signer,
        mocked_sigstore_models,
        mocked_sigstore_verifier,
        tmp_path,
    ):
        trust_config_path = (
            pathlib.Path(__file__).parent
            / "testdata"
            / "custom_trust_config.json"
        )

        serializer = file.Serializer(
            self._file_hasher_factory, allow_symlinks=True
        )
        manifest = serializer.serialize(sample_model_folder)
        signature_path = tmp_path / "model.sig"
        self._sign_manifest(manifest, signature_path, sigstore.Signer)

        mocked_client_trust_config = mocked_sigstore_models["ClientTrustConfig"]
        mocked_custom_config = mock.MagicMock()
        mocked_client_trust_config.from_json.return_value = mocked_custom_config

        verifier = sigstore.Verifier(
            identity="test",
            oidc_issuer="test",
            use_staging=False,
            trust_config=trust_config_path,
        )
        signature = sigstore.Signature.read(signature_path)
        verifier.verify(signature)

        assert mocked_client_trust_config.from_json.called
        call_args = mocked_client_trust_config.from_json.call_args
        assert call_args is not None
        assert isinstance(call_args[0][0], str)
        trust_config_content = json.loads(call_args[0][0])
        assert trust_config_content["mediaType"] == (
            "application/vnd.dev.sigstore.clienttrustconfig.v0.1+json"
        )
        assert "signing_config" in trust_config_content
        assert "trustedRoot" in trust_config_content
