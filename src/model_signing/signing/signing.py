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

"""Machinery for signing and verification of ML models.

The serialization API produces a manifest representation of the models, and we
use that to implement integrity checking of models in different computational
patterns. This means that all manifests need to be kept only in memory.

Hence, for signing, we need a separate class hierarchy to represent the payload.
This is why we introduce `SigningPayload` abstract class here. Every instance of
this class is built via a `from_manifest` method (to allow for classes that need
initialization to be performed only once in their constructor but then convert
multiple manifests into payloads).

Since we need to support multiple signing methods (e.g., Sigstore, own PKI,
BCID), we provide a `Signer` abstract class with a single `sign` method that
takes a signing payload and converts it to a signature in the supported format.
Since signers may only accept payloads in specific formats, the `sign` method
can raise a `TypeError` if the provided `SigningPayload` instance is not
supported (due to typing rules, we cannot just use a subclass type for the
argument).

Every possible signature will be implemented as a subclass of `Signature` class.
The API for signatures only allows writing them to disk and parsing them from a
given path.

Finally, every signature needs to be verified. We pair every `Signer` subclass
with a `Verifier` which takes a signature, verify the authenticity of the
payload and then expand that to a `manifest.Manifest` subclass.
"""

import abc
import pathlib
import sys

from model_signing.manifest import manifest


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


class SigningPayload(metaclass=abc.ABCMeta):
    """Generic payload that we can sign."""

    @classmethod
    @abc.abstractmethod
    def from_manifest(cls, manifest: manifest.Manifest) -> Self:
        """Converts a manifest to the signing payload used for signing.

        Args:
            manifest: the manifest to convert to signing payload.

        Returns:
            An instance of `SigningPayload` or subclass of it.
        """
        pass


class Signature(metaclass=abc.ABCMeta):
    """Generic signature support."""

    @abc.abstractmethod
    def write(self, path: pathlib.Path) -> None:
        """Writes the signature to disk, to the given path.

        Args:
            path: the path to write the signature to.
        """
        pass

    @classmethod
    @abc.abstractmethod
    def read(cls, path: pathlib.Path) -> Self:
        """Reads the signature from disk.

        Does not perform any signature verification, except what is needed to
        parse the signature file.

        Args:
            path: the path to read the signature from.

        Returns:
            An instance of the class which can be passed to a `Verifier` for
            signature and integrity verification.

        Raises:
            ValueError: If the provided path is not deserializable to the format
              expected by the `Signature` (sub)class.
        """
        pass


class Signer(metaclass=abc.ABCMeta):
    """Generic signer for `SigningPayload` objects.

    Every signer is allowed to only support some signing payload formats. Every
    signer produces a signature in its own format. No signer is required to
    support all subclasses of `SigningPayload` or `Signature`.

    Each signer may implement its own mechanism for managing the key material.
    """

    @abc.abstractmethod
    def sign(self, payload: SigningPayload) -> Signature:
        """Signs the provided signing payload.

        Args:
            payload: the `SigningPayload` instance that should be signed.

        Returns:
            A valid signature.

        Raises:
            TypeError: If the `payload` type is not one of the subclasses of
              `SigningPayload` that are supported.
        """
        pass


class Verifier(metaclass=abc.ABCMeta):
    """Generic signature verifier.

    Every subclass of `Verifier` is paired with a subclass of `Signer`. This is
    to ensure that they support the same signing payload and signature formats
    as well as have similar key materials.

    If the signature is valid, the payload is expanded to a `Manifest` instance
    which can then be used to check the model integrity.
    """

    @abc.abstractmethod
    def verify(self, signature: Signature) -> manifest.Manifest:
        """Verifies the signature.

        Args:
            signature: the signature to verify.

        Returns:
            A `manifest.Manifest` instance that represents the model.

        Raises:
            ValueError: If the signature verification fails.
            TypeError: If the signature is not one of the `Signature` subclasses
              accepted by the verifier.
        """
        pass
