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

For signing, we need to convert the manifest to the signing payload. We only
support manifests serialized to in-toto formats described by
https://github.com/in-toto/attestation/tree/main/spec/v1. The envelope format
is DSSE, as described in https://github.com/secure-systems-lab/dsse.

Since we need to support multiple signing methods (e.g., Sigstore, key,
certificate, etc.) , we provide a `Signer` abstract class with a single `sign`
method that takes a signing payload and converts it to a signature in the
supported format.

Every possible signature will be implemented as a subclass of `Signature` class.
The API for signatures only allows writing them to disk and parsing them from a
given path.
TODO: only one signature is supported!

Finally, every signature needs to be verified. We pair every `Signer` subclass
with a `Verifier` which takes a signature, verify the authenticity of the
payload and then expand that to a manifest.
"""

import abc
import pathlib
import sys
from typing import Any, Final

from in_toto_attestation.v1 import statement

from model_signing import manifest
from model_signing._hashing import hashing


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


def _convert_descriptors_to_direct_statement(
    model_manifest: manifest.Manifest, predicate_type: str
) -> statement.Statement:
    """Converts manifest descriptors to an in-toto statement, as subjects.

    Args:
        manifest: The manifest to extract the descriptors from. Assumed valid.
        predicate_type: The predicate_type to use in the in-toto statement.
    """
    subjects = []
    for descriptor in model_manifest.resource_descriptors():
        subject = statement.ResourceDescriptor(
            name=descriptor.identifier,
            digest={"sha256": descriptor.digest.digest_hex},
            annotations={"actual_hash_algorithm": descriptor.digest.algorithm},
        )
        subjects.append(subject.pb)

    return statement.Statement(
        subjects=subjects,
        predicate_type=predicate_type,
        # https://github.com/in-toto/attestation/issues/374
        predicate={"unused": "Unused, just passed due to API requirements"},
    )


class SigningPayload:
    """In-toto payload where the subjects are the model files themselves.

    This payload is supposed to be used for manifests where every file in the
    model is matched with a digest. Because existing tooling only supports
    established hashing algorithms, we annotate every subject with the actual
    hash algorithm used to compute the file digest, and use "sha256" as the
    algorithm name in the digest itself.

    Example (TODO: needs to be updated):
    ```json
    {
      "_type": "https://in-toto.io/Statement/v1",
      "subject": [
        {
          "name": "d0/d1/d2/d3/d4/f0",
          "digest": {
            "sha256": "6efa14..."
          },
          "annotations": {
            "actual_hash_algorithm": "file-sha256"
          }
        },
        {
          "name": "d0/d1/d2/d3/d4/f1",
          "digest": {
            "sha256": "a9bc14..."
          },
          "annotations": {
            "actual_hash_algorithm": "file-sha256"
          }
        },
        {
          "name": "d0/d1/d2/d3/d4/f2",
          "digest": {
            "sha256": "5f597e..."
          },
          "annotations": {
            "actual_hash_algorithm": "file-sha256"
          }
        },
        {
          "name": "d0/d1/d2/d3/d4/f3",
          "digest": {
            "sha256": "eaf677..."
          },
          "annotations": {
            "actual_hash_algorithm": "file-sha256"
          }
        }
      ],
      "predicateType": "https://model_signing/Digests/v0.1",
      "predicate": {
        "unused": "Unused, just passed due to API requirements"
      }
    }
    ```

    If the annotation for a subject is missing, or it does not contain
    actual_hash_algorithm, it should be assumed that the digest is computed via
    the algorithm listed in the digest dictionary (i.e., sha256).

    See also https://github.com/sigstore/sigstore-python/issues/1018.
    """

    predicate_type: Final[str] = "https://model_signing/Digests/v0.1"
    statement: Final[statement.Statement]

    def __init__(self, statement: statement.Statement):
        """Builds an instance of this in-toto payload.

        Don't call this directly in production. Use `from_manifest()` instead.

        Args:
            statement: The DSSE statement representing this in-toto payload.
        """
        self.statement = statement

    @classmethod
    def from_manifest(cls, manifest: manifest.Manifest) -> Self:
        """Converts a manifest to the signing payload used for signing.

        The manifest must be one where every model file is paired with its own
        digest. Currently, this is only `Manifest`.

        Args:
            manifest: the manifest to convert to signing payload.

        Returns:
            An instance of this class.
        """
        statement = _convert_descriptors_to_direct_statement(
            manifest, predicate_type=cls.predicate_type
        )
        return cls(statement)

    @classmethod
    def manifest_from_payload(
        cls, payload: dict[str, Any]
    ) -> manifest.Manifest:
        """Builds a manifest from an in-memory in-toto payload.

        Args:
            payload: the in memory in-toto payload to build a manifest from.

        Returns:
            A manifest that can be converted back to the same payload.
        """
        subjects = payload["subject"]

        items = []
        for subject in subjects:
            path = pathlib.PurePosixPath(subject["name"])
            algorithm = subject["annotations"]["actual_hash_algorithm"]
            digest_value = subject["digest"]["sha256"]
            digest = hashing.Digest(algorithm, bytes.fromhex(digest_value))
            item = manifest.FileManifestItem(path=path, digest=digest)
            items.append(item)

        return manifest.Manifest(items)


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

    Each signer may implement its own mechanism for managing the key material.
    """

    @abc.abstractmethod
    def sign(self, payload: SigningPayload) -> Signature:
        """Signs the provided signing payload.

        Args:
            payload: the `SigningPayload` instance that should be signed.

        Returns:
            A valid signature.
        """
        pass


class Verifier(metaclass=abc.ABCMeta):
    """Generic signature verifier.

    Every subclass of `Verifier` is paired with a subclass of `Signer`. This is
    to ensure that they support the same signature formats as well as have
    similar key materials.

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
