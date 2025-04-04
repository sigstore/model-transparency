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

"""High level API for the verification interface of `model_signing` library.

This module supports configuring the verification method used to verify a model,
before performing the verification.

```python
model_signing.verifying.Config().use_sigstore_verifier(
    identity=identity, oidc_issuer=oidc_provider
).verify("finbert", "finbert.sig")
```

The same verification configuration can be used to verify multiple models:

```python
verifying_config = model_signing.signing.Config().use_elliptic_key_verifier(
    public_key="key.pub"
)

for model in all_models:
    verifying_config.verify(model, f"{model}_sharded.sig")
```

The API defined here is stable and backwards compatible.
"""

from collections.abc import Iterable
import pathlib
import sys

from model_signing import hashing
from model_signing import manifest
from model_signing._signing import sign_certificate as certificate
from model_signing._signing import sign_ec_key as ec_key
from model_signing._signing import sign_sigstore as sigstore
from model_signing._signing import sign_sigstore_pb as sigstore_pb


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


class Config:
    """Configuration to use when verifying models against signatures.

    The verification configuration is needed to determine how to read and verify
    the signature. Given we support multiple signing format, the verification
    settings must match the signing ones.

    The configuration also supports configuring the hashing configuration from
    `model_signing.hashing`. This should also match the configuration used
    during signing. However, by default, we can attempt to guess it from the
    signature.
    """

    def __init__(self):
        """Initializes the default configuration for verification."""
        self._hashing_config = None
        self._verifier = None
        self._uses_sigstore = False

    def verify(
        self, model_path: hashing.PathLike, signature_path: hashing.PathLike
    ):
        """Verifies that a model conforms to a signature.

        Args:
            model_path: The path to the model to verify.

        Raises:
            ValueError: No verifier has been configured.
        """
        if self._verifier is None:
            raise ValueError("Attempting to verify with no configured verifier")

        if self._uses_sigstore:
            signature = sigstore.Signature.read(pathlib.Path(signature_path))
        else:
            signature = sigstore_pb.Signature.read(pathlib.Path(signature_path))

        expected_manifest = self._verifier.verify(signature)

        if self._hashing_config is None:
            self._guess_hashing_config(expected_manifest)
        actual_manifest = self._hashing_config.hash(model_path)

        if actual_manifest != expected_manifest:
            raise ValueError("Signature mismatch")

    def set_hashing_config(self, hashing_config: hashing.Config) -> Self:
        """Sets the new configuration for hashing models.

        After calling this method, the automatic guessing of the hashing
        configuration used during signing is no longer possible from within one
        instance of this class.

        Args:
            hashing_config: The new hashing configuration.

        Returns:
            The new signing configuration.
        """
        self._hashing_config = hashing_config
        return self

    def _guess_hashing_config(self, source_manifest: manifest.Manifest) -> None:
        """Attempts to guess the hashing config from a manifest."""
        args = source_manifest.serialization_type
        method = args["method"]
        # TODO: Once Python 3.9 support is deprecated revert to using `match`
        if method == "files":
            self._hashing_config = hashing.Config().use_file_serialization(
                hashing_algorithm=args["hash_type"],
                allow_symlinks=args["allow_symlinks"],
            )
        elif method == "shards":
            self._hashing_config = hashing.Config().use_shard_serialization(
                hashing_algorithm=args["hash_type"],
                shard_size=args["shard_size"],
                allow_symlinks=args["allow_symlinks"],
            )
        else:
            raise ValueError("Cannot guess the hashing configuration")

    def use_sigstore_verifier(
        self, *, identity: str, oidc_issuer: str, use_staging: bool = False
    ) -> Self:
        """Configures the verification of signatures produced by Sigstore.

        The verifier in this configuration is changed to one that performs
        verification of Sigstore signatures (sigstore bundles signed by
        keyless signing via Sigstore).

        Args:
            identity: The expected identity that has signed the model.
            oidc_issuer: The expected OpenID Connect issuer that provided the
              certificate used for the signature.
            use_staging: Use staging configurations, instead of production. This
              is supposed to be set to True only when testing. Default is False.

        Return:
            The new verification configuration.
        """
        self._uses_sigstore = True
        self._verifier = sigstore.Verifier(
            identity=identity, oidc_issuer=oidc_issuer, use_staging=use_staging
        )
        return self

    def use_elliptic_key_verifier(
        self, *, public_key: hashing.PathLike
    ) -> Self:
        """Configures the verification of signatures generated by a private key.

        The verifier in this configuration is changed to one that performs
        verification of sgistore bundles signed by an elliptic curve private
        key. The public key used in the configuration must match the private key
        used during signing.

        Args:
            public_key: The path to the public key to verify with.

        Return:
            The new verification configuration.
        """
        self._uses_sigstore = False
        self._verifier = ec_key.Verifier(pathlib.Path(public_key))
        return self

    def use_certificate_verifier(
        self, *, certificate_chain: Iterable[hashing.PathLike] = frozenset()
    ) -> Self:
        """Configures the verification of signatures generated by a certificate.

        The verifier in this configuration is changed to one that performs
        verification of sgistore bundles signed by a signing certificate.

        Args:
            certificate_chain: Certificate chain to establish root of trust. If
              empty, the operating system's one is used.

        Return:
            The new verification configuration.
        """
        self._uses_sigstore = False
        self._verifier = certificate.Verifier(
            [pathlib.Path(c) for c in certificate_chain]
        )
        return self
