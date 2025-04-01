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

"""High level API for the verification interface of model_signing library.

Users should use this API to verify the integrity of models, rather than using
the internals of the library. We guarantee backwards compatibility only for the
API defined in `hash.py`, `sign.py` and `verify.py` at the root level of the
library.
"""

import os
import pathlib
import sys
from typing import Optional

from model_signing import hash
from model_signing.signing import sign_sigstore as sigstore


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


def verify(
    model_path: os.PathLike,
    signature_path: os.PathLike,
    *,
    identity: str,
    oidc_issuer: Optional[str] = None,
    use_staging: bool = False,
):
    """Verifies that a model conforms to a signature.

    Currently, this assumes signatures over DSSE, using Sigstore. We will add
    support for more cases in a future change.

    Args:
        model_path: the path to the model to verify.
        signature_path: the path to the signature to check.
        identity: The expected identity that has signed the model.
        oidc_issuer: The expected OpenID Connect issuer that provided the
          certificate used for the signature.
        use_staging: Use staging configurations, instead of production. This
          is supposed to be set to True only when testing. Default is False.
    """
    Config().set_sigstore_dsse_verifier(
        identity=identity, oidc_issuer=oidc_issuer, use_staging=use_staging
    ).verify(model_path, signature_path)


class Config:
    """Configuration to use when verifying models against signatures.

    The verification configuration is used to decouple between serialization
    formats and verification types. Having configured the serialization format,
    this configuration class supports setting up the verification parameters.
    These should match the signing one.
    """

    def __init__(self):
        """Initializes the default configuration for verification."""
        self._hashing_config = hash.Config()
        self._verifier = None

    def verify(self, model_path: os.PathLike, signature_path: os.PathLike):
        """Verifies that a model conforms to a signature.

        Args:
            model_path: the path to the model to verify.
            signature_path: the path to the signature to check.
        """
        signature = sigstore.SigstoreSignature.read(
            pathlib.Path(signature_path)
        )
        expected_manifest = self._verifier.verify(signature)
        actual_manifest = self._hashing_config.hash(model_path)

        if actual_manifest != expected_manifest:
            raise ValueError("Signature mismatch")

    def set_hashing_config(self, hashing_config: hash.Config) -> Self:
        """Sets the new configuration for hashing models.

        Args:
            hashing_config: the new hashing configuration.

        Returns:
            The new signing configuration.
        """
        self._hashing_config = hashing_config
        return self

    def set_sigstore_dsse_verifier(
        self,
        *,
        identity: str,
        oidc_issuer: Optional[str] = None,
        use_staging: bool = False,
    ) -> Self:
        """Configures the verification of a Sigstore signature over DSSE.

        Only one verifier can be configured. Currently, we only support Sigstore
        in the API, but the CLI supports signing with PKI, BYOK and no
        signing/verification.  We will merge the configurations in a subsequent
        change.

        Args:
            identity: The expected identity that has signed the model.
            oidc_issuer: The expected OpenID Connect issuer that provided the
              certificate used for the signature.
            use_staging: Use staging configurations, instead of production. This
              is supposed to be set to True only when testing. Default is False.

        Return:
            The new verification configuration.
        """
        self._verifier = sigstore.SigstoreVerifier(
            identity=identity, oidc_issuer=oidc_issuer, use_staging=use_staging
        )
        return self
