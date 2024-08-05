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

from model_signing.hashing import memory
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
    set the name field to ".", and use the digest as the one resulting from the
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
          "name": ".",
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
        descriptor = statement.ResourceDescriptor(name=".", digest=digest).pb

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


def _convert_descriptors_to_hashed_statement(
    manifest: manifest_module.Manifest,
    *,
    predicate_type: str,
    predicate_top_level_name: str,
):
    """Converts manifest descriptors to an in-toto statement with payload.

    Args:
        manifest: The manifest to extract the descriptors from. Assumed valid.
        predicate_type: The predicate_type to use in the in-toto statement.
        predicate_top_level_name: Name to use in the payload for the array of
          the subjects.
    """
    hasher = memory.SHA256()
    subjects = []
    for descriptor in manifest.resource_descriptors():
        hasher.update(descriptor.digest.digest_value)
        subjects.append({
            "name": descriptor.identifier,
            "digest": descriptor.digest.digest_hex,
            "algorithm": descriptor.digest.algorithm,
        })

    digest = {"sha256": hasher.compute().digest_hex}
    descriptor = statement.ResourceDescriptor(name=".", digest=digest).pb

    return statement.Statement(
        subjects=[descriptor],
        predicate_type=predicate_type,
        predicate={predicate_top_level_name: subjects},
    )


class DigestOfDigestsIntotoPayload(IntotoPayload):
    """In-toto payload where the subject is a digest of digests of model files.

    This payload is supposed to be used for manifests where every file in the
    model is matched with a digest. Because existing tooling only supports
    established hashing algorithms, we record every such digest in the predicate
    part and compute a hash for the subject by using sha256 on the concatenation
    of the file hashes. To ensure determinism, the hashes are sorted
    alphabetically by filename.

    Example:
    ```json
    {
      "_type": "https://in-toto.io/Statement/v1",
      "subject": [
        {
          "name": ".",
          "digest": {
            "sha256": "18b5a4..."
          }
        }
      ],
      "predicateType": "https://model_signing/DigestOfDigests/v0.1",
      "predicate": {
        "files": [
          {
            "digest": "6efa14...",
            "algorithm": "file-sha256",
            "name": "d0/d1/d2/d3/d4/f0"
          },
          {
            "digest": "a9bc14...",
            "algorithm": "file-sha256",
            "name": "d0/d1/d2/d3/d4/f1"
          },
          {
            "digest": "5f597e...",
            "algorithm": "file-sha256",
            "name": "d0/d1/d2/d3/d4/f2"
          },
          {
            "digest": "eaf677...",
            "algorithm": "file-sha256",
            "name": "d0/d1/d2/d3/d4/f3"
          }
        ]
      }
    }
    ```

    A missing predicate, or a predicate for which an entry does not have valid
    name, digest, or algorithm should be considered invalid and fail integrity
    verification.

    See also https://github.com/sigstore/sigstore-python/issues/1018.
    """

    predicate_type: Final[str] = "https://model_signing/DigestOfDigests/v0.1"

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
        digest. Currently, this is only `FileLevelManifest`.

        Args:
            manifest: the manifest to convert to signing payload.

        Returns:
            An instance of `DigestOfDigestsIntotoPayload`.

        Raises:
            TypeError: If the manifest is not `FileLevelManifest`.
        """
        if not isinstance(manifest, manifest_module.FileLevelManifest):
            raise TypeError("Only FileLevelManifest is supported")

        statement = _convert_descriptors_to_hashed_statement(
            manifest,
            predicate_type=cls.predicate_type,
            predicate_top_level_name="files",
        )
        return cls(statement)


class DigestOfShardDigestsIntotoPayload(IntotoPayload):
    """In-toto payload where the subject is a digest of digests of file shards.

    This payload is supposed to be used for manifests where every file shard in
    the model is matched with a digest. Because existing tooling only supports
    established hashing algorithms, we record every such digest in the predicate
    part and compute a hash for the subject by using sha256 on the concatenation
    of the shard hashes. To ensure determinism, the hashes are sorted
    by file shard (alphabetically by name, then ordered by start offset).

    Example:
    ```json
    {
      "_type": "https://in-toto.io/Statement/v1",
      "subject": [
        {
          "name": ".",
          "digest": {
            "sha256": "18b5a4..."
          }
        }
      ],
      "predicateType": "https://model_signing/DigestOfShardDigests/v0.1",
      "predicate": {
        "shards": [
          {
            "digest": "6efa14...",
            "algorithm": "file-sha256-1000000",
            "name": "d0/d1/d2/d3/d4/f0:0:16"
          },
          {
            "digest": "a9bc14...",
            "algorithm": "file-sha256-1000000",
            "name": "d0/d1/d2/d3/d4/f1:0:16"
          },
          {
            "digest": "5f597e...",
            "algorithm": "file-sha256-1000000",
            "name": "d0/d1/d2/d3/d4/f2:0:16"
          },
          {
            "digest": "eaf677...",
            "algorithm": "file-sha256-1000000",
            "name": "d0/d1/d2/d3/d4/f3:0:16"
          }
        ]
      }
    }
    ```

    A missing predicate, or a predicate for which an entry does not have valid
    name, digest, or algorithm should be considered invalid and fail integrity
    verification.

    See also https://github.com/sigstore/sigstore-python/issues/1018.
    """

    predicate_type: Final[str] = (
        "https://model_signing/DigestOfShardDigests/v0.1"
    )

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

        The manifest must be one where every model shard is paired with its own
        digest. Currently, this is only `ShardLevelManifest`.

        Args:
            manifest: the manifest to convert to signing payload.

        Returns:
            An instance of `DigestOfDigestsIntotoPayload`.

        Raises:
            TypeError: If the manifest is not `ShardLevelManifest`.
        """
        if not isinstance(manifest, manifest_module.ShardLevelManifest):
            raise TypeError("Only ShardLevelManifest is supported")

        statement = _convert_descriptors_to_hashed_statement(
            manifest,
            predicate_type=cls.predicate_type,
            predicate_top_level_name="shards",
        )
        return cls(statement)


def _convert_descriptors_to_direct_statement(
    manifest: manifest_module.Manifest, predicate_type: str
):
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
        predicate={"unused":"Unused, just passed due to API requirements"},
    )


class DigestsIntotoPayload(IntotoPayload):
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
        digest. Currently, this is only `FileLevelManifest`.

        Args:
            manifest: the manifest to convert to signing payload.

        Returns:
            An instance of `DigestOfDigestsIntotoPayload`.

        Raises:
            TypeError: If the manifest is not `FileLevelManifest`.
        """
        if not isinstance(manifest, manifest_module.FileLevelManifest):
            raise TypeError("Only FileLevelManifest is supported")

        statement = _convert_descriptors_to_direct_statement(
            manifest, predicate_type=cls.predicate_type
        )
        return cls(statement)


class ShardDigestsIntotoPayload(IntotoPayload):
    """In-toto payload where the subjects are the model shards themselves.

    This payload is supposed to be used for manifests where every file shard in
    the model is matched with a digest. Because existing tooling only supports
    established hashing algorithms, we annotate every subject with the actual
    hash algorithm used to compute the file digest, and use "sha256" as the
    algorithm name in the digest itself.

    Example:
    ```json
    {
      "_type": "https://in-toto.io/Statement/v1",
      "subject": [
        {
          "name": "d0/d1/d2/d3/d4/f0:0:16",
          "digest": {
            "sha256": "6efa14..."
          },
          "annotations": {
            "actual_hash_algorithm": "file-sha256-1000000"
          }
        },
        {
          "name": "d0/d1/d2/d3/d4/f1:0:16",
          "digest": {
            "sha256": "a9bc14..."
          },
          "annotations": {
            "actual_hash_algorithm": "file-sha256-1000000"
          }
        },
        {
          "name": "d0/d1/d2/d3/d4/f2:0:16",
          "digest": {
            "sha256": "5f597e..."
          },
          "annotations": {
            "actual_hash_algorithm": "file-sha256-1000000"
          }
        },
        {
          "name": "d0/d1/d2/d3/d4/f3:0:16",
          "digest": {
            "sha256": "eaf677..."
          },
          "annotations": {
            "actual_hash_algorithm": "file-sha256-1000000"
          }
        }
      ],
      "predicateType": "https://model_signing/ShardDigests/v0.1",
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

    predicate_type: Final[str] = (
        "https://model_signing/ShardDigests/v0.1"
    )

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

        The manifest must be one where every model shard is paired with its own
        digest. Currently, this is only `ShardLevelManifest`.

        Args:
            manifest: the manifest to convert to signing payload.

        Returns:
            An instance of `DigestOfDigestsIntotoPayload`.

        Raises:
            TypeError: If the manifest is not `ShardLevelManifest`.
        """
        if not isinstance(manifest, manifest_module.ShardLevelManifest):
            raise TypeError("Only ShardLevelManifest is supported")

        statement = _convert_descriptors_to_direct_statement(
            manifest, predicate_type=cls.predicate_type
        )
        return cls(statement)
