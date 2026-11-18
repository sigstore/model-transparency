# Copyright 2026 The Sigstore Authors
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

"""Tests for RFC 3161 timestamp verification."""

import base64
from datetime import UTC, datetime
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import rfc3161_client
from sigstore_models.bundle import v1 as bundle_pb

from model_signing._signing import sign_sigstore_pb


class _Verifier(sign_sigstore_pb.Verifier):
    def _verify_bundle(self, bundle, verification_time):
        raise NotImplementedError


def _material(timestamp: bytes):
    timestamp_data = bundle_pb.TimestampVerificationData(
        rfc3161_timestamps=[
            bundle_pb.RFC3161SignedTimestamp(
                signed_timestamp=base64.b64encode(timestamp)
            )
        ]
    )
    return SimpleNamespace(timestamp_verification_data=timestamp_data)


def _authority(mocker, certificates=None):
    authority = mocker.Mock()
    authority.certificates.return_value = certificates or [
        mocker.sentinel.leaf,
        mocker.sentinel.root,
    ]
    authority.validity_period_start = datetime(2025, 1, 1, tzinfo=UTC)
    authority.validity_period_end = datetime(2027, 1, 1, tzinfo=UTC)
    root = mocker.Mock()
    root.get_timestamp_authorities.return_value = [authority]
    return authority, root


def test_timestamp_is_verified_over_signature_bytes(mocker):
    raw_timestamp = b"raw timestamp response"
    signature = b"signature bytes"
    timestamp = datetime(2026, 1, 2, tzinfo=UTC)
    response = SimpleNamespace(tst_info=SimpleNamespace(gen_time=timestamp))
    decode = mocker.patch.object(
        rfc3161_client, "decode_timestamp_response", return_value=response
    )
    builder = mocker.patch.object(rfc3161_client, "VerifierBuilder")
    verifier = builder.return_value.build.return_value
    authority, root = _authority(mocker)
    load_root = mocker.patch.object(
        sign_sigstore_pb, "_load_trusted_root", return_value=root
    )

    result = sign_sigstore_pb.verify_timestamp(
        _material(raw_timestamp), signature
    )

    assert result == timestamp
    load_root.assert_called_once_with(None)
    decode.assert_called_once_with(raw_timestamp)
    builder.assert_called_once_with(
        tsa_certificate=mocker.sentinel.leaf,
        intermediates=[],
        roots=[mocker.sentinel.root],
    )
    verifier.verify_message.assert_called_once_with(response, signature)
    authority.certificates.assert_called_once_with(allow_expired=True)


def test_timestamp_requires_trusted_authority(mocker):
    root = mocker.Mock()
    root.get_timestamp_authorities.return_value = []
    mocker.patch.object(sign_sigstore_pb, "_load_trusted_root", return_value=root)
    mocker.patch.object(
        rfc3161_client,
        "decode_timestamp_response",
        return_value=mocker.Mock(),
    )

    with pytest.raises(ValueError, match="No timestamp authorities"):
        sign_sigstore_pb.verify_timestamp(_material(b"timestamp"), b"sig")


def test_missing_timestamp_is_compatible_unless_required(mocker):
    material = SimpleNamespace(timestamp_verification_data=None)
    load_root = mocker.patch.object(sign_sigstore_pb, "_load_trusted_root")

    assert sign_sigstore_pb.verify_timestamp(material, b"signature") is None
    with pytest.raises(ValueError, match="timestamp is required"):
        sign_sigstore_pb.verify_timestamp(
            material, b"signature", require_timestamp=True
        )
    load_root.assert_not_called()


def test_invalid_timestamp_fails_closed(mocker):
    response = SimpleNamespace(
        tst_info=SimpleNamespace(gen_time=datetime(2026, 1, 2, tzinfo=UTC))
    )
    mocker.patch.object(
        rfc3161_client, "decode_timestamp_response", return_value=response
    )
    builder = mocker.patch.object(rfc3161_client, "VerifierBuilder")
    builder.return_value.build.return_value.verify_message.side_effect = (
        rfc3161_client.VerificationError("signature mismatch")
    )
    _, root = _authority(mocker)
    mocker.patch.object(
        sign_sigstore_pb, "_load_trusted_root", return_value=root
    )

    with pytest.raises(ValueError, match="Invalid RFC 3161 timestamp"):
        sign_sigstore_pb.verify_timestamp(
            _material(b"timestamp"),
            b"wrong signature",
        )


def test_timestamp_must_be_within_authority_validity(mocker):
    response = SimpleNamespace(
        tst_info=SimpleNamespace(gen_time=datetime(2028, 1, 1, tzinfo=UTC))
    )
    mocker.patch.object(
        rfc3161_client, "decode_timestamp_response", return_value=response
    )
    _, root = _authority(mocker)
    mocker.patch.object(
        sign_sigstore_pb, "_load_trusted_root", return_value=root
    )
    mocker.patch.object(rfc3161_client, "VerifierBuilder")

    with pytest.raises(ValueError, match="untrusted authority"):
        sign_sigstore_pb.verify_timestamp(_material(b"timestamp"), b"signature")


def test_loads_client_config_or_standalone_trusted_root(tmp_path):
    config_path = (
        Path(__file__).parent / "testdata" / "custom_trust_config.json"
    )
    document = json.loads(config_path.read_text())
    root_path = tmp_path / "trusted-root.json"
    root_path.write_text(json.dumps(document["trustedRoot"]))

    from_config = sign_sigstore_pb._load_trusted_root(config_path)
    standalone = sign_sigstore_pb._load_trusted_root(root_path)

    assert from_config.get_timestamp_authorities()
    assert standalone.get_timestamp_authorities()


def test_default_trust_uses_sigstore_production(mocker):
    config = mocker.Mock()
    production = mocker.patch.object(
        sign_sigstore_pb.sigstore_models.ClientTrustConfig,
        "production",
        return_value=config,
    )

    assert sign_sigstore_pb._load_trusted_root(None) is config.trusted_root
    production.assert_called_once_with()


def test_verifier_loads_trust_lazily_once(mocker):
    root = mocker.sentinel.root
    load_root = mocker.patch.object(
        sign_sigstore_pb, "_load_trusted_root", return_value=root
    )
    verifier = _Verifier()

    load_root.assert_not_called()
    assert verifier._trusted_root is root
    assert verifier._trusted_root is root
    load_root.assert_called_once_with(None)
