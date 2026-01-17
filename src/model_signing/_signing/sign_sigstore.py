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
from typing import cast

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

_DEFAULT_CLIENT_ID = "sigstore"
_DEFAULT_CLIENT_SECRET = ""


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
        path.write_text(self.bundle.to_json(), encoding="utf-8")

    @classmethod
    @override
    def read(cls, path_or_content: signing.SignatureInput) -> Self:
        """Read a signature from a file path, JSON string, or bytes.

        Args:
            path_or_content:
                - A path to a JSON signature file
                - A JSON string containing the signature
                - Bytes containing the JSON signature (UTF-8 encoded)

        Returns:
            The loaded signature.
        """
        content = signing.read_text_input(path_or_content)
        return cls(sigstore_models.Bundle.from_json(content))


class Signer(signing.Signer):
    """Signing using Sigstore."""

    def __init__(
        self,
        *,
        oidc_issuer: str | None = None,
        use_ambient_credentials: bool = True,
        use_staging: bool = False,
        identity_token: str | None = None,
        force_oob: bool = False,
        client_id: str | None = None,
        client_secret: str | None = None,
        trust_config: pathlib.Path | None = None,
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
            force_oob: If True, forces an out-of-band (OOB) OAuth flow. If set,
              the OAuth authentication will not attempt to open the default web
              browser. Instead, it will display a URL and code for manual
              authentication. Default is False, which means the browser will be
              opened automatically if possible.
            identity_token: An explicit identity token to use when signing,
              taking precedence over any ambient credential or OAuth workflow.
             client_id: An optional client ID to use when performing OIDC-based
              authentication. This is typically used to identify the
              application making the request to the OIDC provider. If not
              provided, the default client ID configured by Sigstore will be
              used.
            client_secret: An optional client secret to use along with the
              client ID when authenticating with the OIDC provider. This is
              required for confidential clients that need to prove their
              identity to the OIDC provider. If not provided, it is assumed
              that the client is public or the provider does not require a
              secret.
            trust_config: A path to a custom trust configuration. When
              provided, the signature verification process will rely on the
              supplied PKI and trust configurations, instead of the default
              Sigstore setup. If not specified, the default Sigstore
              configuration is used.
        """
        if use_staging:
            trust_config = sigstore_models.ClientTrustConfig.staging()
        elif trust_config:
            trust_config = sigstore_models.ClientTrustConfig.from_json(
                trust_config.read_text()
            )
        else:
            trust_config = sigstore_models.ClientTrustConfig.production()

        if not oidc_issuer:
            oidc_issuer = trust_config.signing_config.get_oidc_url()

        self._issuer = sigstore_oidc.Issuer(oidc_issuer)
        self._signing_context = (
            sigstore_signer.SigningContext.from_trust_config(trust_config)
        )
        self._use_ambient_credentials = use_ambient_credentials
        self._identity_token = identity_token
        self._force_oob = force_oob
        self._client_id = client_id or _DEFAULT_CLIENT_ID
        self._client_secret = client_secret or _DEFAULT_CLIENT_SECRET

    def _get_identity_token(self) -> sigstore_oidc.IdentityToken:
        """Obtains an identity token to use in signing.

        The precedence matches that of sigstore-python:
        1) Explicitly supplied identity token
        2) Ambient credential detected in the environment, if enabled
        3) Interactive OAuth flow
        """
        if self._identity_token:
            return sigstore_oidc.IdentityToken(
                self._identity_token, self._client_id
            )
        if self._use_ambient_credentials:
            token = sigstore_oidc.detect_credential(self._client_id)
            if token:
                return sigstore_oidc.IdentityToken(token, self._client_id)

        return self._issuer.identity_token(
            force_oob=self._force_oob,
            client_id=self._client_id,
            client_secret=self._client_secret,
        )

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
        self,
        *,
        identity: str,
        oidc_issuer: str,
        use_staging: bool = False,
        trust_config: pathlib.Path | None = None,
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
            trust_config: A path to a custom trust configuration. When provided,
              the signature verification process will rely on the supplied
              PKI and trust configurations, instead of the default Sigstore
              setup. If not specified, the default Sigstore configuration
              is used.
        """
        if trust_config:
            trust_config = sigstore_models.ClientTrustConfig.from_json(
                trust_config.read_text()
            )
        elif use_staging:
            trust_config = sigstore_models.ClientTrustConfig.staging()
        else:
            trust_config = sigstore_models.ClientTrustConfig.production()

        self._verifier = sigstore_verifier.Verifier(
            trusted_root=trust_config.trusted_root
        )

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
