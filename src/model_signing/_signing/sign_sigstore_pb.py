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

"""Sigstore based signature, signers and verifiers, using protobuf.

The difference between this module and `sign_sigstore` is that here we use
Sigstore via the protobuf specs instead of `sigstore-python`. This is to enable
support for traditional signing and verification. These require additional data
to be stored in the sigstore bundle used for the signature but `sigstore-python`
validation does not allow those.
"""

import abc
import base64
from datetime import datetime
import json
import logging
import pathlib
import sys
from typing import cast
import urllib.error
import urllib.request

import rfc3161_client
from sigstore_models.bundle import v1 as bundle_pb
from typing_extensions import override

from model_signing._signing import signing


logger = logging.getLogger(__name__)


_TSA_CLIENT_TIMEOUT: int = 5
_USER_AGENT: str = "model-signing"


def _request_timestamp(
    url: str, signature: bytes
) -> rfc3161_client.TimeStampResponse:
    """Request a timestamp from a TSA for the given signature."""
    try:
        timestamp_request = (
            rfc3161_client.TimestampRequestBuilder()
            .hash_algorithm(rfc3161_client.base.HashAlgorithm.SHA256)
            .data(signature)
            .nonce(nonce=True)
            .build()
        )
    except ValueError as error:
        raise ValueError(f"invalid TSA request: {error}") from error

    req = urllib.request.Request(
        url,
        data=timestamp_request.as_bytes(),
        headers={
            "Content-Type": "application/timestamp-query",
            "User-Agent": _USER_AGENT,
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=_TSA_CLIENT_TIMEOUT) as resp:
            response_bytes = resp.read()
    except urllib.error.URLError as error:
        raise ValueError(f"TSA request failed: {error}") from error

    try:
        return rfc3161_client.decode_timestamp_response(response_bytes)
    except ValueError as error:
        raise ValueError(f"invalid TSA response: {error}") from error


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


# The media type to use when creating the protobuf based Sigstore bundle
_BUNDLE_MEDIA_TYPE: str = "application/vnd.dev.sigstore.bundle.v0.3+json"


def pae(raw_payload: bytes) -> bytes:
    """Generates the PAE encoding of statement from the payload.

    This is an internal of `sigstore_python`, but since in this module and
    classes derived from the signer and verifier defined here we cannot use
    `sigstore_python`, we have to reimplement this.

    See https://github.com/secure-systems-lab/dsse/blob/v1.0.0/protocol.md
    for details.

    Args:
        raw_payload: The raw payload to encode.

    Returns:
        The encoded statement from the payload.
    """
    payload_type = signing._IN_TOTO_JSON_PAYLOAD_TYPE
    payload_type_length = len(payload_type)
    payload_length = len(raw_payload)
    pae_str = f"DSSEv1 {payload_type_length} {payload_type} {payload_length}"
    return b" ".join([pae_str.encode("utf-8"), raw_payload])


def pae_compat(raw_payload: bytes) -> bytes:
    """Generates the PAE encoding of statement from the payload.

    This is the same as `pae`, but using the version as defined in v0.2.0 of the
    `model_signing` library. Due to a bug in that implementation, signatures
    generated at that version have to be verified using this compat patch. The
    issue is that the raw payload, which is bytes, is added to a string and then
    encoded back as bytes, so we get additional escape characters included.

    Args:
        raw_payload: The raw payload to encode.

    Returns:
        The encoded statement from the payload.
    """
    payload_type = signing._IN_TOTO_JSON_PAYLOAD_TYPE
    payload_type_length = len(payload_type)
    payload_length = len(raw_payload)
    # Notice bug here!
    pae_str = (
        f"DSSEV1 {payload_type_length} {payload_type} "
        f"{payload_length} {raw_payload}"
    )
    return pae_str.encode("utf-8")


class Signature(signing.Signature):
    """Sigstore signature support, wrapping around `bundle_pb.Bundle`."""

    def __init__(self, bundle: bundle_pb.Bundle):
        """Builds an instance of this signature.

        Args:
            bundle: the sigstore bundle (in `bundle_pb.Bundle` format).
        """
        self.bundle = bundle

    @override
    def write(self, path: pathlib.Path) -> None:
        path.write_text(self.bundle.to_json(), encoding="utf-8")

    @classmethod
    @override
    def read(cls, path: pathlib.Path) -> Self:
        content = path.read_text(encoding="utf-8")
        parsed_dict = json.loads(content)

        # adjust parsed_dict due to previous usage of protobufs
        if "tlogEntries" not in parsed_dict["verificationMaterial"]:
            parsed_dict["verificationMaterial"]["tlogEntries"] = []
        if "publicKey" in parsed_dict["verificationMaterial"]:
            if "hint" not in parsed_dict["verificationMaterial"]["publicKey"]:
                parsed_dict["verificationMaterial"]["publicKey"]["hint"] = None
            for k in ["rawBytes", "keyDetails"]:
                if k in parsed_dict["verificationMaterial"]["publicKey"]:
                    del parsed_dict["verificationMaterial"]["publicKey"][k]

        return cls(bundle_pb.Bundle.from_dict(parsed_dict))


class Signer(signing.Signer):
    """Signer for traditional signing.

    This is subclassed for each traditional signing method we support.
    """


class Verifier(signing.Verifier):
    """Verifier for traditional signature verification.

    This is subclassed for each traditional signing method we support.
    """

    @override
    def _verify_signed_content(
        self, signature: signing.Signature
    ) -> tuple[str, bytes]:
        # We are guaranteed to only use the local signature type
        signature = cast(Signature, signature)
        bundle = signature.bundle

        # Since the bundle is done via protobuf, check media type first
        if bundle.media_type != _BUNDLE_MEDIA_TYPE:
            raise ValueError(
                f"Invalid sigstore bundle, got media type {bundle.media_type} "
                f"but expected {_BUNDLE_MEDIA_TYPE}"
            )

        return self._verify_bundle(bundle)

    @abc.abstractmethod
    def _verify_bundle(self, bundle: bundle_pb.Bundle) -> tuple[str, bytes]:
        """Verifies the bundle to extract the payload type and payload.

        Since the bundle is generated via proto, we need to do more checks to
        replace what `verify_dsse` from `sigstore_python` does.
        """


def request_timestamp(
    signature_bytes: bytes, tsa_url: str
) -> bundle_pb.TimestampVerificationData:
    """Requests a timestamp from a TSA and returns verification data.

    Args:
        signature_bytes: The signature bytes to timestamp.
        tsa_url: The URL of the RFC 3161 Timestamp Authority.

    Returns:
        TimestampVerificationData to include in the bundle.
    """
    response = _request_timestamp(tsa_url, signature_bytes)

    return bundle_pb.TimestampVerificationData(
        rfc3161_timestamps=[
            bundle_pb.RFC3161SignedTimestamp(
                signed_timestamp=base64.b64encode(response.as_bytes())
            )
        ]
    )


def get_timestamp_from_bundle(
    verification_material: bundle_pb.VerificationMaterial,
) -> datetime | None:
    """Extracts the timestamp from the bundle's verification material.

    Args:
        verification_material: The bundle's verification material.

    Returns:
        The timestamp datetime if present and valid, None otherwise.
    """
    ts_data = verification_material.timestamp_verification_data
    if not ts_data or not ts_data.rfc3161_timestamps:
        return None

    ts = ts_data.rfc3161_timestamps[0]
    try:
        response = rfc3161_client.decode_timestamp_response(
            base64.b64decode(ts.signed_timestamp)
        )
        return response.tst_info.gen_time
    except (ValueError, KeyError) as error:
        logger.warning(f"Failed to decode timestamp from bundle: {error}")
        return None
