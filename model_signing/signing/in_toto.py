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

"""Signing payloads for models as in-toto statements.

To generate the signing payload we convert model manifests to in-toto formats,
as described by https://github.com/in-toto/attestation/tree/main/spec/v1. The
envelope format is DSSE, see https://github.com/secure-systems-lab/dsse.
"""

from typing import Final, Self

from in_toto_attestation.v1 import statement
from typing_extensions import override

from model_signing.manifest import manifest as manifest_module
from model_signing.signing import signing


class IntotoPayload(signing.SigningPayload):
    """A generic payload in in-toto format.

    This class is abstract for now as we will support multiple payload formats
    below.

    Each subclass defines a constant for the predicate type class attribute
    defined below.
    """

    predicate_type: Final[str]


class SingleDigestIntotoPayload(IntotoPayload):
    """In-toto payload where the model is serialized to just one digest.

    In this case, we encode the model as the only subject of the statement. We
    don't set the name field, and use the digest as the one resulting from the
    model serialization.

    However, since we use custom hashing algorithms, but these are not supported
    by existing tools, we claim that the digest algorithm is sha-256 and include
    the real digest in the predicate.

    Example:
    ```json
    {
      "_type": "https://in-toto.io/Statement/v1",
      "subject": [
        {
          "digest": {
            "sha256": "3aab065c...."
          }
        }
      ],
      "predicateType": "https://model_signing/Digest/v0.1",
      "predicate": {
        "actual_hash_algorithm": "file-sha256"
      }
    }
    ```

    If the predicate is missing (or does not set "actual_hash_algorithm"), it
    should be assumed that the digest is actually computed via the algorithm
    present in the resource descriptor (i.e., sha256).

    See also https://github.com/sigstore/sigstore-python/issues/1018.
    """

    predicate_type: Final[str] = "https://model_signing/Digest/v0.1"

    def __init__(self, *, digest_hex: str, digest_algorithm: str):
        """Builds an instance of this in-toto payload.

        Don't call this directly in production. Use `from_manifest()` instead.

        Args:
            digest_hex: the hexadecimal, human readable, digest of the subject.
            digest_algorithm: the algorithm used to compute the digest.
        """
        digest = {"sha256": digest_hex}
        descriptor = statement.ResourceDescriptor(digest=digest).pb

        self.statement = statement.Statement(
            subjects=[descriptor],
            predicate_type=self.predicate_type,
            predicate={"actual_hash_algorithm": digest_algorithm},
        )

    @classmethod
    @override
    def from_manifest(cls, manifest: manifest_module.Manifest) -> Self:
        """Converts a manifest to the signing payload used for signing.

        The manifest must be a `DigestManifest` instance.

        Args:
            manifest: the manifest to convert to signing payload.

        Returns:
            An instance of `SingleDigestIntotoPayload`.

        Raises:
            TypeError: If the manifest is not `DigestManifest`.
        """
        if not isinstance(manifest, manifest_module.DigestManifest):
            raise TypeError("Only DigestManifest is supported")

        # guaranteed to have exactly one item
        subject = list(manifest.resource_descriptors())[0]
        digest = subject.digest
        return cls(
            digest_hex=digest.digest_hex,
            digest_algorithm=digest.algorithm,
        )
