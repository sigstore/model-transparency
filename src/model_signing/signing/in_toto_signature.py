# Copyright (c) 2024, NVIDIA CORPORATION.  All rights reserved.
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

"""Support for signing intoto payloads into sigstore bundles."""

import json
import pathlib
import sys

from sigstore_protobuf_specs.dev.sigstore.bundle import v1 as bundle_pb
from typing_extensions import override

from model_signing.manifest import manifest as manifest_module
from model_signing.signature import signing as signature_signing
from model_signing.signature import verifying as signature_verifying
from model_signing.signing import in_toto
from model_signing.signing import signing


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


class IntotoSignature(signing.Signature):
    def __init__(self, bundle: bundle_pb.Bundle):
        self._bundle = bundle

    @override
    def write(self, path: pathlib.Path) -> None:
        path.write_text(self._bundle.to_json())

    @classmethod
    @override
    def read(cls, path: pathlib.Path) -> Self:
        bundle = bundle_pb.Bundle().from_json(path.read_text())
        return cls(bundle)

    def to_manifest(self) -> manifest_module.Manifest:
        payload = json.loads(self._bundle.dsse_envelope.payload)
        return in_toto.IntotoPayload.manifest_from_payload(payload)


class IntotoSigner(signing.Signer):
    def __init__(self, sig_signer: signature_signing.Signer):
        self._sig_signer = sig_signer

    @override
    def sign(self, payload: signing.SigningPayload) -> IntotoSignature:
        if not isinstance(payload, in_toto.IntotoPayload):
            raise TypeError("only IntotoPayloads are supported")
        bundle = self._sig_signer.sign(payload.statement)
        return IntotoSignature(bundle)


class IntotoVerifier(signing.Verifier):
    def __init__(self, sig_verifier: signature_verifying.Verifier):
        self._sig_verifier = sig_verifier

    @override
    def verify(self, signature: signing.Signature) -> manifest_module.Manifest:
        if not isinstance(signature, IntotoSignature):
            raise TypeError("only IntotoSignature is supported")
        self._sig_verifier.verify(signature._bundle)
        return signature.to_manifest()
