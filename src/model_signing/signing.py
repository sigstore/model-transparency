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

"""High level API for the signing interface of `model_signing` library.

The module allows signing a model with a default configuration:

```python
model_signing.signing.sign("finbert", "finbert.sig")
```

The module allows customizing the signing configuration before signing:

```python
model_signing.signing.Config().use_elliptic_key_signer(private_key="key").sign(
    "finbert", "finbert.sig"
)
```

The same signing configuration can be used to sign multiple models:

```python
signing_config = model_signing.signing.Config().use_elliptic_key_signer(
    private_key="key"
)

for model in all_models:
    signing_config.sign(model, f"{model}_sharded.sig")
```

The API defined here is stable and backwards compatible.
"""

from collections.abc import Iterable
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


def sign(model_path: hashing.PathLike, signature_path: hashing.PathLike):
    """Signs a model using the default configuration.

    In this default configuration we sign using Sigstore and the default hashing
    configuration from `model_signing.hashing`.

    The resulting signature is in the Sigstore bundle format.

    Args:
        model_path: the path to the model to sign.
        signature_path: the path of the resulting signature.
    """
    Config().sign(model_path, signature_path)


class Config:
    """Configuration to use when signing models.

    Currently, we support signing with Sigstore (both the public
    instance and staging instance), signing with private keys,
    signing with signing certificates, and signing with custom
    PKI configurations using the `--trust_config` option.
    This allows users to bring their own trust configuration
    to sign and verify models. Other signing modes may be
    added in the future.
    """

    def __init__(self):
        """Initializes the default configuration for signing."""
        self._hashing_config = hashing.Config()
        # lazy initialize default signer at signing to avoid network calls
        self._signer = None

    def sign(
        self, model_path: hashing.PathLike, signature_path: hashing.PathLike
    ):
        """Signs a model using the current configuration.

        Args:
            model_path: The path to the model to sign.
            signature_path: The path of the resulting signature.
        """
        if not self._signer:
            self._signer = self.use_sigstore_signer()
        manifest = self._hashing_config.hash(model_path)
        payload = signing.Payload(manifest)
        signature = self._signer.sign(payload)
        signature.write(pathlib.Path(signature_path))

    def set_hashing_config(self, hashing_config: hashing.Config) -> Self:
        """Sets the new configuration for hashing models.

        Args:
            hashing_config: The new hashing configuration.

        Returns:
            The new signing configuration.
        """
        self._hashing_config = hashing_config
        return self

    def use_sigstore_signer(
        self,
        *,
        oidc_issuer: Optional[str] = None,
        use_ambient_credentials: bool = False,
        use_staging: bool = False,
        force_oob: bool = False,
        identity_token: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        trust_config: Optional[pathlib.Path] = None,
    ) -> Self:
        """Configures the signing to be performed with Sigstore.

        The signer in this configuration is changed to one that performs signing
        with Sigstore.

        Args:
            oidc_issuer: An optional OpenID Connect issuer to use instead of the
              default production one. Only relevant if `use_staging = False`.
              Default is empty, relying on the Sigstore configuration.
            use_ambient_credentials: Use ambient credentials (also known as
              Workload Identity). Default is False. If ambient credentials
              cannot be used (not available, or option disabled), a flow to get
              signer identity via OIDC will start.
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
            trust_config: A path to a custom trust configuration. When provided,
              the signature verification process will rely on the supplied
              PKI and trust configurations, instead of the default Sigstore
              setup. If not specified, the default Sigstore configuration
              is used.


        Return:
            The new signing configuration.
        """
        self._signer = sigstore.Signer(
            oidc_issuer=oidc_issuer,
            use_ambient_credentials=use_ambient_credentials,
            use_staging=use_staging,
            identity_token=identity_token,
            force_oob=force_oob,
            client_id=client_id,
            client_secret=client_secret,
            trust_config=trust_config,
        )
        return self

    def use_elliptic_key_signer(
        self, *, private_key: hashing.PathLike, password: Optional[str] = None
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
        self._signer = ec_key.Signer(pathlib.Path(private_key), password)
        return self

    def use_certificate_signer(
        self,
        *,
        private_key: hashing.PathLike,
        signing_certificate: hashing.PathLike,
        certificate_chain: Iterable[hashing.PathLike],
    ) -> Self:
        """Configures the signing to be performed using signing certificates.

        The signer in this configuration is changed to one that performs signing
        using cryptographic signing certificates.

        Args:
            private_key: The path to the private key to use for signing.
            signing_certificate: The path to the signing certificate.
            certificate_chain: Optional paths to other certificates to establish
              a chain of trust.

        Return:
            The new signing configuration.
        """
        self._signer = certificate.Signer(
            pathlib.Path(private_key),
            pathlib.Path(signing_certificate),
            [pathlib.Path(c) for c in certificate_chain],
        )
        return self

    def use_pkcs11_signer(
        self, *, pkcs11_uri: str, module_paths: Iterable[str] = frozenset()
    ) -> Self:
        """Configures the signing to be performed using PKCS #11.

        The signer in this configuration is changed to one that performs signing
        using a private key based on elliptic curve cryptography.

        Args:
            pkcs11_uri: The PKCS11 URI.
            module_paths: Optional list of paths of PKCS #11 modules.

        Return:
            The new signing configuration.
        """
        try:
            from model_signing._signing import sign_pkcs11 as pkcs11
        except ImportError as e:
            raise RuntimeError(
                "PKCS #11 functionality requires the 'pkcs11' extra. "
                "Install with 'pip install model-signing[pkcs11]'."
            ) from e
        self._signer = pkcs11.Signer(pkcs11_uri, module_paths)
        return self

    def use_pkcs11_certificate_signer(
        self,
        *,
        pkcs11_uri: str,
        signing_certificate: pathlib.Path,
        certificate_chain: Iterable[pathlib.Path],
        module_paths: Iterable[str] = frozenset(),
    ) -> Self:
        """Configures the signing to be performed using signing certificates.

        The signer in this configuration is changed to one that performs signing
        using cryptographic certificates.

        Args:
            pkcs11_uri: The PKCS #11 URI.
            signing_certificate: The path to the signing certificate.
            certificate_chain: Optional paths to other certificates to establish
              a chain of trust.
            module_paths: Optional list of paths of PKCS #11 modules.

        Return:
            The new signing configuration.
        """
        try:
            from model_signing._signing import sign_pkcs11 as pkcs11
        except ImportError as e:
            raise RuntimeError(
                "PKCS #11 functionality requires the 'pkcs11' extra. "
                "Install with 'pip install model-signing[pkcs11]'."
            ) from e

        self._signer = pkcs11.CertSigner(
            pkcs11_uri,
            signing_certificate,
            certificate_chain,
            module_paths=module_paths,
        )
        return self
