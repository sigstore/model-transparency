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
"""This package provides the functionality to sign and verify models
with sigstore."""
from typing import Optional

from absl import logging as log
from in_toto_attestation.v1 import statement
from sigstore import dsse
from sigstore import oidc
from sigstore import sign
from sigstore.verify import verifier as sig_verifier
from sigstore.verify import policy as sig_policy
from sigstore.verify import models as sig_models
from sigstore_protobuf_specs.dev.sigstore.bundle import v1 as bundle_pb

from model_signing.signature.signing import Signer
from model_signing.signature.verifying import Verifier
from model_signing.signature.verifying import VerificationError


class SigstoreSigner(Signer):
    """Provides a Signer that uses sigstore for signing."""

    CLIENT_ID = "sigstore"

    def __init__(self, disable_ambient: bool = True, id_provider: str = None):
        token = self.__get_identity_token(disable_ambient, id_provider)
        if not token:
            raise ValueError("No identity token supplied or detected!")
        log.info(
            f"Signing identity provider: {token.expected_certificate_subject}")
        log.info(f"Signing identity: {token.identity}")
        self._signer = sign.Signer(
            identity_token=token,
            signing_ctx=sign.SigningContext.production(),
        )

    @staticmethod
    def __convert_stmnt(stmnt: statement.Statement) -> dsse.Statement:
        subjects = stmnt.pb.subject
        sigstore_subjects = []
        for s in subjects:
            sigstore_subjects.append(
                dsse._Subject(
                    name=s.name,
                    digest={"sha256": s.digest["sha256"]},
                )
            )
        return dsse._StatementBuilder(
            predicate_type=stmnt.pb.predicate_type,
            predicate=stmnt.pb.predicate,
            subjects=sigstore_subjects,
        ).build()

    @staticmethod
    def __get_identity_token(
        disable_ambient: bool = True,
        id_provider: Optional[str] = None,
    ) -> Optional[oidc.IdentityToken]:
        token: oidc.IdentityToken
        if not disable_ambient:
            return oidc.detect_credential()

        issuer = oidc.Issuer(id_provider) if id_provider \
            else oidc.Issuer.production()
        token = issuer.identity_token(
            client_id=SigstoreSigner.CLIENT_ID, force_oob=True
        )
        return token

    def sign(self, stmnt: statement.Statement) -> bundle_pb.Bundle:
        return self._signer.sign_dsse(self.__convert_stmnt(stmnt))._inner


class SigstoreVerifier(Verifier):
    """Provides a verifier using sigstore."""

    def __init__(self, oidc_provider: str, identity: str):
        self._verifier = sig_verifier.Verifier.production()
        self._policy = sig_policy.Identity(
            identity=identity,
            issuer=oidc_provider,
        )

    def verify(self, bundle: bundle_pb.Bundle) -> None:
        try:
            sig_bundle = sig_models.Bundle(bundle)
            _ = self._verifier.verify_dsse(sig_bundle, self._policy)
        except Exception as e:
            raise VerificationError(str(e))
