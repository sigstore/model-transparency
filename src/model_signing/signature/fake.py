# Copyright (c) 2024, NVIDIA CORPORATION.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Functionality to generate and verify bundles without signing."""

from google.protobuf import json_format
from in_toto_attestation.v1 import statement
from sigstore_protobuf_specs.dev.sigstore.bundle import v1 as bundle_pb
from sigstore_protobuf_specs.dev.sigstore.common import v1 as common_pb
from sigstore_protobuf_specs.io import intoto as intoto_pb

from model_signing.signature.encoding import PAYLOAD_TYPE
from model_signing.signature.signing import Signer
from model_signing.signature.verifying import Verifier


class FakeSigner(Signer):
    """Provides a Signer that just returns the bundle."""

    def sign(self, stmnt: statement.Statement) -> bundle_pb.Bundle:
        env = intoto_pb.Envelope(
            payload=json_format.MessageToJson(stmnt.pb).encode(),
            payload_type=PAYLOAD_TYPE,
            signatures=[intoto_pb.Signature(sig=b"", keyid=None)],
        )
        bdl = bundle_pb.Bundle(
            media_type="application/vnd.dev.sigstore.bundle.v0.3+json",
            verification_material=bundle_pb.VerificationMaterial(
                public_key=common_pb.PublicKey(
                    raw_bytes=None,
                    key_details=common_pb.PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
                )
            ),
            dsse_envelope=env,
        )
        return bdl


class FakeVerifier(Verifier):
    """Provides a fake verifier that always passes."""

    def verify(self, bundle: bundle_pb.Bundle) -> None:
        pass
