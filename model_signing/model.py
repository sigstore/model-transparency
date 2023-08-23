# Copyright Google LLC
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
# See the License for the specific language governing perepo_managerissions and
# limitations under the License.

from sigstore.sign import (
    Signer,
)
from sigstore._internal.oidc import (
    DEFAULT_AUDIENCE,
)
from sigstore.oidc import (
    Issuer,
    detect_credential,
)
from sigstore_protobuf_specs.dev.sigstore.bundle.v1 import Bundle
from sigstore.verify import (
    VerificationMaterials,
    policy,
    Verifier,
)
from sigstore.verify.models import (
    VerificationMaterials,
    VerificationResult,
)

import os, io, hashlib, base64, json
from pathlib import Path
from typing import Optional
from serialize import Serializer

#TODO: Update this class to have a status instead of success.
class BaseResult:
    def __init__(self, success: bool = True, reason: str = "success"):
        self.success = success
        self.reason = reason
    def __bool__(self) -> bool:
        return self.success
    def __str__(self) -> str:
        return f"success=\"{self.success}\" reason=\"{self.reason}\""

class SignatureResult(BaseResult):
    pass

class SigstoreSigner():
    def __init__(self, 
                 use_ambiant:bool = True,
                 start_default_browser: bool = False,
                 name: str = None):
        self.signer = Signer.production()
        self.use_ambiant = use_ambiant
        self.start_default_browser = start_default_browser
        if not start_default_browser:
            # TODO(https://github.com/sigstore/sigstore-python/issues/666): Update this code.
            os.environ["SIGSTORE_OAUTH_FORCE_OOB"] = "1"
        self.name = name
        self.client_id = DEFAULT_AUDIENCE
    
    def get_identity_token(self) -> Optional[str]:
        token: str
        client_id = self.client_id
        if self.use_ambiant:
            token = detect_credential()
            # Happy path: we've detected an ambient credential, so we can return early.
            if token:
                return token

        #TODO(): Support staging for testing.
        if self.name is not None:
            issuer = Issuer(self.name)
        else:
            issuer = Issuer.production()

        token = issuer.identity_token(client_id=client_id)

        return token

    def sign(self, inputfn: Path, signaturefn: Path) -> SignatureResult:
        try:
            token = self.get_identity_token()
            if not token:
                raise ValueError("No identity token supplied or detected!")

            contentio = io.BytesIO(Serializer.serialize(inputfn, signaturefn))
            result = self.signer.sign(input_=contentio, identity_token=token)
            with signaturefn.open(mode="w") as b:
                print(result._to_bundle().to_json(), file=b)
            return SignatureResult()
        except Exception as e:
            return SignatureResult(success=False, reason=f"exception caught: {str(e)}")
        raise ValueError("unreachable")

#TODO: re-visit error handling and use a verbosity mode
# to avoid leaking info
class VerificationResult(BaseResult):
    pass

class SigstoreVerifier():
    def __init__(self, oidc_provider: str, email: str):
        self.oidc_provider = oidc_provider
        self.email = email
        self.verifier = Verifier.production()

    def verify(self, inputfn: Path, signaturefn: Path, offline: bool) -> VerificationResult:
        try:
            bundle_bytes = signaturefn.read_bytes()
            bundle = Bundle().from_json(bundle_bytes)

            material: tuple[Path, VerificationMaterials]
            contentio = io.BytesIO(Serializer.serialize(inputfn, signaturefn))
            material = VerificationMaterials.from_bundle(input_=contentio, bundle=bundle, offline=offline)
            policy_ = policy.Identity(
                identity=self.email,
                issuer=self.oidc_provider,
            )
            result = self.verifier.verify(materials=material, policy=policy_)
            if result:
                return VerificationResult()
            return VerificationResult(success = False, reason = result.reason)
        except Exception as e:
            return VerificationResult(success=False, reason=f"exception caught: {str(e)}")
        raise ValueError("unreachable")
