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

"""High level API for the signing interface of model_signing library.

Users should use this API to sign models, rather than using the internals of the
library. We guarantee backwards compatibility only for the API defined in
`hashing.py`, `signing.py` and `verifying.py` at the root level of the library.
"""

from collections.abc import Iterable
import os
import pathlib
import sys
from typing import Optional

from model_signing import hashing
from model_signing._signing import sign_certificate as certificate
from model_signing._signing import sign_ec_key as ec_key
from model_signing._signing import sign_sigstore as sigstore
from model_signing._signing import signing


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


def sign(model_path: os.PathLike, signature_path: os.PathLike):
    """Signs a model using the default configuration.

    Args:
        model_path: the path to the model to sign.
        signature_path: the path of the resulting signature.
    """
    Config().sign(model_path, signature_path)


class Config:
    """Configuration to use when signing models.

    The signing configuration is used to decouple between serialization formats
    and signing types. This configuration class allows setting up the
    serialization format, the method to convert a manifest to a signing payload
    and the engine used for signing (currently, only supporting Sigstore at this
    level).
    """

    def __init__(self):
        """Initializes the default configuration for signing."""
        self._hashing_config = hashing.Config()
        self.use_sigstore_signer()

    def sign(self, model_path: os.PathLike, signature_path: os.PathLike):
        """Signs a model using the current configuration.

        Args:
            model_path: the path to the model to sign.
            signature_path: the path of the resulting signature.
        """
        manifest = self._hashing_config.hash(model_path)
        payload = signing.Payload(manifest)
        signature = self._signer.sign(payload)
        signature.write(pathlib.Path(signature_path))

    def set_hashing_config(self, hashing_config: hashing.Config) -> Self:
        """Sets the new configuration for hashing models.

        Args:
            hashing_config: the new hashing configuration.

        Returns:
            The new signing configuration.
        """
        self._hashing_config = hashing_config
        return self

    def use_sigstore_signer(
        self,
        *,
        oidc_issuer: Optional[str] = None,
        use_ambient_credentials: bool = True,
        use_staging: bool = False,
        identity_token: Optional[str] = None,
    ) -> Self:
        """Configures the signing to be performed with Sigstore.

        The signer in this configuration is changed to one that performs signing
        with Sigstore, as configured.

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

        Return:
            The new signing configuration.
        """
        self._signer = sigstore.Signer(
            oidc_issuer=oidc_issuer,
            use_ambient_credentials=use_ambient_credentials,
            use_staging=use_staging,
            identity_token=identity_token,
        )
        return self

    def use_elliptic_key_signer(
        self, *, private_key: pathlib.Path, password: Optional[str] = None
    ) -> Self:
        """Configures the signing to be performed using elliptic curve keys.

        The signer in this configuration is changed to one that performs signing
        using a private key based on elliptic curve cryptography.

        Args:
            private_key: The path to the private key to use for signing.
            password: An optional password for the key, if encrypted.

        Return:
            The new signing configuration.
        """
        self._signer = ec_key.Signer(private_key, password)
        return self

    def use_certificate_signer(
        self,
        *,
        private_key: pathlib.Path,
        signing_certificate: pathlib.Path,
        certificate_chain: Iterable[pathlib.Path],
    ) -> Self:
        """Configures the signing to be performed using signing certificates.

        The signer in this configuration is changed to one that performs signing
        using cryptographic certificates.

        Args:
            private_key: The path to the private key to use for signing.
            signing_certificate: The path to the signing certificate.
            certificate_chain: Optional paths to other certificates to establish
              a chain of trust.

        Return:
            The new signing configuration.
        """
        self._signer = certificate.Signer(
            private_key, signing_certificate, certificate_chain
        )
        return self
