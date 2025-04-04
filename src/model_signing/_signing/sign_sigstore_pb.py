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
import pathlib
import sys
from typing import cast

from sigstore_protobuf_specs.dev.sigstore.bundle import v1 as bundle_pb
from typing_extensions import override

from model_signing._signing import signing


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
        payload: The raw payload to encode.

    Returns:
        The encoded statement from the payload.
    """
    payload_type = signing._IN_TOTO_JSON_PAYLOAD_TYPE
    payload_type_length = len(payload_type)
    payload_length = len(raw_payload)
    pae_str = f"DSSEv1 {payload_type_length} {payload_type} {payload_length}"
    return b" ".join([pae_str.encode("utf-8"), raw_payload])


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
        path.write_text(self.bundle.to_json())

    @classmethod
    @override
    def read(cls, path: pathlib.Path) -> Self:
        content = path.read_text()
        return cls(bundle_pb.Bundle().from_json(content))


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
