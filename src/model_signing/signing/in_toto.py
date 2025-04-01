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

import pathlib
import sys
from typing import Any, Final

from in_toto_attestation.v1 import statement
from typing_extensions import override

from model_signing import manifest as manifest_module
from model_signing._hashing import hashing
from model_signing.signing import signing


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


def _convert_descriptors_to_direct_statement(
    manifest: manifest_module.Manifest, predicate_type: str
) -> statement.Statement:
    """Converts manifest descriptors to an in-toto statement, as subjects.

    Args:
        manifest: The manifest to extract the descriptors from. Assumed valid.
        predicate_type: The predicate_type to use in the in-toto statement.
    """
    subjects = []
    for descriptor in manifest.resource_descriptors():
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


class IntotoPayload(signing.SigningPayload):
    """In-toto payload where the subjects are the model files themselves.

    This payload is supposed to be used for manifests where every file in the
    model is matched with a digest. Because existing tooling only supports
    established hashing algorithms, we annotate every subject with the actual
    hash algorithm used to compute the file digest, and use "sha256" as the
    algorithm name in the digest itself.

    Example:
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
    @override
    def from_manifest(cls, manifest: manifest_module.Manifest) -> Self:
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
    @override
    def manifest_from_payload(
        cls, payload: dict[str, Any]
    ) -> manifest_module.Manifest:
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
            item = manifest_module.FileManifestItem(path=path, digest=digest)
            items.append(item)

        return manifest_module.Manifest(items)
