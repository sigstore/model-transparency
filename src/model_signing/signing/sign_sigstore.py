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

import json
import pathlib
import sys
from typing import Optional

from google.protobuf import json_format
from sigstore import dsse as sigstore_dsse
from sigstore import models as sigstore_models
from sigstore import oidc as sigstore_oidc
from sigstore import sign as sigstore_signer
from sigstore import verify as sigstore_verifier
from typing_extensions import override

from model_signing.hashing import hashing
from model_signing.manifest import manifest
from model_signing.signing import as_bytes
from model_signing.signing import in_toto
from model_signing.signing import signing


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


_IN_TOTO_JSON_PAYLOAD_TYPE: str = "application/vnd.in-toto+json"
_IN_TOTO_STATEMENT_TYPE: str = "https://in-toto.io/Statement/v1"


class SigstoreSignature(signing.Signature):
    """Sigstore signature support, wrapping around `sigstore_models.Bundle`."""

    def __init__(self, bundle: sigstore_models.Bundle):
        """Builds an instance of this signature.

        Args:
            bundle: the Sigstore `Bundle` to wrap around.
        """
        self.bundle = bundle

    @override
    def write(self, path: pathlib.Path) -> None:
        """Writes the signature to disk, to the given path.

        The Sigstore `Bundle` is written in JSON format, per the
        canonicalization defined by the `sigstore-python` library.

        Args:
            path: the path to write the signature to.
        """
        path.write_text(self.bundle.to_json())

    @classmethod
    @override
    def read(cls, path: pathlib.Path) -> Self:
        """Reads the signature from disk.

        Does not perform any signature verification, except what is needed to
        parse the signature file.

        Args:
            path: the path to read the signature from.

        Returns:
            A `SigstoreSignature` object wrapping a Sigstore `Bundle`.

        Raises:
            ValueError: If the Sigstore `Bundle` could not be deserialized from
              the contents of the file pointed to by `path`.
        """
        content = path.read_text()
        return cls(sigstore_models.Bundle.from_json(content))


class SigstoreSigner(signing.Signer):
    """Signing machinery using Sigstore.

    We want to sign both digests and in-toto statements, so we provide two
    separate subclasses for the signing. This class will just handle the common
    parts needed to work with Sigstore.
    """

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


class SigstoreArtifactSigner(SigstoreSigner):
    """A Sigstore signer that only signs artifacts.

    In our case, this instance is only used to sign `as_bytes.BytesPayload`
    signing payloads.
    """

    @override
    def sign(self, payload: signing.SigningPayload) -> SigstoreSignature:
        """Signs the provided signing payload.

        Args:
            payload: the payload to sign.

        Returns:
            A `SigstoreSignature` object.

        Raises:
            TypeError: If the `payload` type is not `as_bytes.BytesPayload`.
        """
        if not isinstance(payload, as_bytes.BytesPayload):
            raise TypeError("Only `BytesPayload` payloads are supported")

        token = self._get_identity_token()
        with self._signing_context.signer(token) as signer:
            bundle = signer.sign_artifact(payload.digest)

        return SigstoreSignature(bundle)


class SigstoreDSSESigner(SigstoreSigner):
    """A Sigstore signer that only signs DSSE statements.

    In our case, this instance is only used to sign `in_toto.IntotoPayload`
    signing payloads.
    """

    @override
    def sign(self, payload: signing.SigningPayload) -> SigstoreSignature:
        """Signs the provided signing payload.

        Args:
            payload: the payload to sign.

        Returns:
            A `SigstoreSignature` object.

        Raises:
            TypeError: If the `payload` type is not `as_bytes.BytesPayload`.
        """
        if not isinstance(payload, in_toto.IntotoPayload):
            raise TypeError("Only `IntotoPayload` payloads are supported")

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

        return SigstoreSignature(bundle)


class SigstoreVerifier(signing.Verifier):
    """Signature verification machinery using Sigstore.

    We want to be able to verify signatures generated from either digests or
    in-toto statements, so we provide two separate subclasses for the
    verification. This class will just handle the common parts needed to work
    with Sigstore.
    """

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

        # TODO: https://github.com/sigstore/model-transparency/issues/271 -
        # Support additional verification policies
        self._policy = sigstore_verifier.policy.Identity(
            identity=identity, issuer=oidc_issuer
        )


class SigstoreArtifactVerifier(SigstoreVerifier):
    """A Sigstore verifier for signatures on simple digests.

    This class only accepts signatures generated by `SigstoreArtifactSigner`.
    """

    def __init__(
        self,
        expected_digest: bytes,
        *,
        identity: str,
        oidc_issuer: str,
        use_staging: bool = False,
    ):
        """Initializes this verifier.

        Since the signature was generated over a digest, we need to pass the
        expected digest as an argument here (as that is what Sigstore's
        `verify_artifact` expects). Hence, in order to use this class, the model
        on disk needs to be first serialized and the obtained digest can be
        passed to signature verification. This is in reverse compared to
        manifest based signatures where signature verification results in a
        manifest of all expected files and then other layers in the library can
        verify the model integrity (optionally with additional policies).

        Args:
            expected_digest: Expected digest. Must match what was signed.
            identity: The expected identity that has signed the model.
            oidc_issuer: The expected OpenID Connect issuer that provided the
              certificate used for the signature.
            use_staging: Use staging configurations, instead of production. This
              is supposed to be set to True only when testing. Default is False.
        """
        super().__init__(
            identity=identity, oidc_issuer=oidc_issuer, use_staging=use_staging
        )
        self._expected_digest = expected_digest

    @override
    def verify(self, signature: signing.Signature) -> manifest.DigestManifest:
        """Verifies the signature.

        Args:
            signature: the signature to verify.

        Returns:
            A `manifest.DigestManifest` instance that represents the model as a
            single hash. If the function returns without raising an exception,
            then verification succeeded.

        Raises:
            ValueError: If the signature verification fails.
            TypeError: If the signature type is not `SigstoreSignature`.
        """
        if not isinstance(signature, SigstoreSignature):
            raise TypeError("Only `SigstoreSignature` signatures are supported")

        self._verifier.verify_artifact(
            input_=self._expected_digest,
            bundle=signature.bundle,
            policy=self._policy,
        )

        digest = hashing.Digest("sha256", self._expected_digest)
        return manifest.DigestManifest(digest)


class SigstoreDSSEVerifier(SigstoreVerifier):
    """A Sigstore verifier for signatures on simple digests.

    This class only accepts signatures generated by `SigstoreArtifactSigner`.
    """

    @override
    def verify(self, signature: signing.Signature) -> manifest.Manifest:
        """Verifies the signature.

        Args:
            signature: the signature to verify.

        Returns:
            A manifest that represents the model when it was signed.

        Raises:
            ValueError: If the signature verification fails, or if the DSSE
              envelope is not in the expected format.
            TypeError: If the signature type is not `SigstoreSignature`.
        """
        if not isinstance(signature, SigstoreSignature):
            raise TypeError("Only `SigstoreSignature` signatures are supported")

        payload_type, payload = self._verifier.verify_dsse(
            bundle=signature.bundle, policy=self._policy
        )

        if payload_type != _IN_TOTO_JSON_PAYLOAD_TYPE:
            raise ValueError(
                f"Expected DSSE payload {_IN_TOTO_JSON_PAYLOAD_TYPE}, "
                f"but got {payload_type}"
            )

        payload = json.loads(payload)

        if payload["_type"] != _IN_TOTO_STATEMENT_TYPE:
            raise ValueError(
                f"Expected in-toto {_IN_TOTO_STATEMENT_TYPE} payload, "
                f"but got {payload['_type']}"
            )

        return in_toto.IntotoPayload.manifest_from_payload(payload)
