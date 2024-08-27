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

"""Empty signing infrastructure.

This is only used to test the signing and verification machinery. It can also be
used as a default implementation in cases where some of the machinery doesn't
need to do anything (e.g., in testing or in cases where verification is being
done from outside the library).
"""

import pathlib
import sys

from typing_extensions import override

from model_signing.manifest import manifest
from model_signing.signing import signing


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


class EmptySigningPayload(signing.SigningPayload):
    """An empty signing payload, mostly just for testing."""

    @classmethod
    @override
    def from_manifest(cls, manifest: manifest.Manifest) -> Self:
        """Converts a manifest to the signing payload used for signing.

        Args:
            manifest: the manifest to convert to signing payload.

        Returns:
            An instance of `EmptySigningPayload`.
        """
        del manifest  # unused
        return cls()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented

        return True  # all instances are equal


class EmptySignature(signing.Signature):
    """Empty signature, mostly for testing.

    Can also be used in cases where the signing result does not need to
    follow the rest of the signing machinery in this library (e.g., it is
    verified only by tooling that assume a different flow, or the existing
    signing machinery already manages writing signatures as a side effect of the
    signing process).
    """

    @override
    def write(self, path: pathlib.Path) -> None:
        """Writes the signature to disk, to the given path.

        Since the signature is empty this function actually does nothing, it's
        here just to match the API.

        Args:
            path: the path to write the signature to. Ignored.
        """
        del path  # unused

    @classmethod
    @override
    def read(cls, path: pathlib.Path) -> Self:
        """Reads the signature from disk.

        Since the signature is empty, this does nothing besides just returning
        an instance of `EmptySignature`.

        Args:
            path: the path to read the signature from. Ignored.

        Returns:
            An instance of `EmptySignature`.
        """
        del path  # unused
        return cls()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented

        return True  # all instances are equal


class EmptySigner(signing.Signer):
    """A signer that only produces `EmptySignature` objects, for testing."""

    @override
    def sign(self, payload: signing.SigningPayload) -> EmptySignature:
        """Signs the provided signing payload.

        Args:
            payload: the `SigningPayload` instance that should be signed.

        Returns:
            An `EmptySignature` object.
        """
        del payload  # unused
        return EmptySignature()


class EmptyVerifier(signing.Verifier):
    """Verifier that accepts only `EmptySignature` objects.

    Rather than producing a manifest out of thin air, the verifier also fails to
    verify the signature, even if it is in the accepted `EmptySignature` format.
    """

    @override
    def verify(self, signature: signing.Signature) -> manifest.Manifest:
        """Verifies the signature.

        Args:
            signature: the signature to verify.

        Raises:
            TypeError: If the signature is not an `EmptySignature` instance.
            ValueError: If the signature is an `EmptySignature` instance. This
              simulates failing signature verification.
        """
        if isinstance(signature, EmptySignature):
            raise ValueError("Signature verification failed")
        raise TypeError("Only `EmptySignature` instances are supported")
