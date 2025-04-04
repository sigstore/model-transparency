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

"""Sigstore based signature, signers and verifiers."""

import pathlib
import sys
from typing import Optional, cast

from google.protobuf import json_format
from sigstore import dsse as sigstore_dsse
from sigstore import models as sigstore_models
from sigstore import oidc as sigstore_oidc
from sigstore import sign as sigstore_signer
from sigstore import verify as sigstore_verifier
from typing_extensions import override

from model_signing._signing import signing


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


class Signature(signing.Signature):
    """Sigstore signature support, wrapping around `sigstore_models.Bundle`."""

    def __init__(self, bundle: sigstore_models.Bundle):
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
        return cls(sigstore_models.Bundle.from_json(content))


class Signer(signing.Signer):
    """Signing using Sigstore."""

    def __init__(
        self,
        *,
        oidc_issuer: Optional[str] = None,
        use_ambient_credentials: bool = True,
        use_staging: bool = False,
        identity_token: Optional[str] = None,
    ):
        """Initializes Sigstore signers.

        Needs to set-up a signing context to use the public goods instance and
        machinery for getting an identity token to use in signing.

        Args:
            oidc_issuer: An optional OpenID Connect issuer to use instead of the
              default production one. Only relevant if `use_staging = False`.
              Default is empty, relying on the Sigstore configuration.
            use_ambient_credentials: Use ambient credentials (also known as
              Workload Identity). Default is True. If ambient credentials cannot
              be used (not available, or option disabled), a flow to get signer
              identity via OIDC will start.
            use_staging: Use staging configurations, instead of production. This
              is supposed to be set to True only when testing. Default is False.
            identity_token: An explicit identity token to use when signing,
              taking precedence over any ambient credential or OAuth workflow.
        """
        if use_staging:
            self._signing_context = sigstore_signer.SigningContext.staging()
            self._issuer = sigstore_oidc.Issuer.staging()
        else:
            self._signing_context = sigstore_signer.SigningContext.production()
            if oidc_issuer is not None:
                self._issuer = sigstore_oidc.Issuer(oidc_issuer)
            else:
                self._issuer = sigstore_oidc.Issuer.production()

        self._use_ambient_credentials = use_ambient_credentials
        self._identity_token = identity_token

    def _get_identity_token(self) -> sigstore_oidc.IdentityToken:
        """Obtains an identity token to use in signing.

        The precedence matches that of sigstore-python:
        1) Explicitly supplied identity token
        2) Ambient credential detected in the environment, if enabled
        3) Interactive OAuth flow
        """
        if self._identity_token:
            return sigstore_oidc.IdentityToken(self._identity_token)
        if self._use_ambient_credentials:
            token = sigstore_oidc.detect_credential()
            if token:
                return sigstore_oidc.IdentityToken(token)

        return self._issuer.identity_token(force_oob=True)

    @override
    def sign(self, payload: signing.Payload) -> Signature:
        # We need to convert from in-toto statement to Sigstore's DSSE
        # version. They both contain the same contents, but there is no way
        # to coerce one type to the other.
        # See also: https://github.com/sigstore/sigstore-python/issues/1076
        statement = sigstore_dsse.Statement(
            json_format.MessageToJson(payload.statement.pb).encode("utf-8")
        )

        token = self._get_identity_token()
        with self._signing_context.signer(token) as signer:
            bundle = signer.sign_dsse(statement)

        return Signature(bundle)


class Verifier(signing.Verifier):
    """Signature verification using Sigstore."""

    def __init__(
        self, *, identity: str, oidc_issuer: str, use_staging: bool = False
    ):
        """Initializes Sigstore verifiers.

        When verifying a signature, we also check an identity policy: the
        certificate must belong to a given "identity", and must be issued by a
        given OpenID Connect issuer.

        Args:
            identity: The expected identity that has signed the model.
            oidc_issuer: The expected OpenID Connect issuer that provided the
              certificate used for the signature.
            use_staging: Use staging configurations, instead of production. This
              is supposed to be set to True only when testing. Default is False.
        """
        if use_staging:
            self._verifier = sigstore_verifier.Verifier.staging()
        else:
            self._verifier = sigstore_verifier.Verifier.production()

        self._policy = sigstore_verifier.policy.Identity(
            identity=identity, issuer=oidc_issuer
        )

    @override
    def _verify_signed_content(
        self, signature: signing.Signature
    ) -> tuple[str, bytes]:
        # We are guaranteed to only use the local signature type
        signature = cast(Signature, signature)
        bundle = signature.bundle
        return self._verifier.verify_dsse(bundle=bundle, policy=self._policy)
