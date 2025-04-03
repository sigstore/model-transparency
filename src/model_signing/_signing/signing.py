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

Since we need to support multiple signing methods (e.g., Sigstore, key,
certificate, etc.) , we provide a `Signer` abstract class with a single `sign`
method that takes a signing payload and converts it to a signature in the
supported format.

Finally, every signature needs to be verified. We pair every `Signer` subclass
with a `Verifier` which takes a signature, verify the authenticity of the
payload and then expand that to a manifest.

Regarding the data formats, for signing, we need to convert the manifest to the
signing payload. We only support manifests serialized to in-toto formats
described by https://github.com/in-toto/attestation/tree/main/spec/v1. The
envelope format is DSSE, as described in
https://github.com/secure-systems-lab/dsse. The signature is in a Sigstore
bundle format over the DSSE payload. The format is described at
https://docs.sigstore.dev/about/bundle/.
"""

import abc
import json
import pathlib
import sys
from typing import Any

from in_toto_attestation.v1 import statement

from model_signing import manifest
from model_signing._hashing import hashing
from model_signing._hashing import memory


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


# The expected in-toto payload type for the signature.
_IN_TOTO_JSON_PAYLOAD_TYPE: str = "application/vnd.in-toto+json"


# The expected in-toto statement type for the signature.
_IN_TOTO_STATEMENT_TYPE: str = "https://in-toto.io/Statement/v1"


# The expected model signature predicate type.
_PREDICATE_TYPE: str = "https://model_signing/signature/v1.0"


def dsse_payload_to_manifest(dsse_payload: dict[str, Any]) -> manifest.Manifest:
    """Builds a manifest from the DSSE payload read from a signature.

    The payload here is a dictionary that represents the payload part of the
    DSSE envelope contained in the Sigstore bundle.

    Args:
        payload: The in-toto DSSE envelope to convert to manifest.

    Returns:
        A manifest representing the signed model.

    Raises:
        ValueError: The payload cannot be deserialized to a manifest.
    """
    obtained_predicate_type = dsse_payload["predicateType"]
    if obtained_predicate_type != _PREDICATE_TYPE:
        raise ValueError(
            f"Predicate type mismatch, expected {_PREDICATE_TYPE}, "
            f"got {obtained_predicate_type}"
        )

    subjects = dsse_payload["subject"]
    if len(subjects) != 1:
        raise ValueError(f"Expected only one subject, got {subjects}")

    model_name = subjects[0]["name"]
    expected_digest = subjects[0]["digest"]["sha256"]

    predicate = dsse_payload["predicate"]
    serialization_args = predicate["serialization"]
    serialization = manifest.SerializationType.from_args(serialization_args)

    hasher = memory.SHA256()
    items = []
    for resource in predicate["resources"]:
        name = resource["name"]
        algorithm = resource["algorithm"]
        digest_value = resource["digest"]
        digest = hashing.Digest(algorithm, bytes.fromhex(digest_value))
        hasher.update(digest.digest_value)
        items.append(serialization.new_item(name, digest))

    obtained_digest = hasher.compute().digest_hex
    if obtained_digest != expected_digest:
        raise ValueError(
            f"Manifest is inconsistent. Root digest is {expected_digest}, "
            f"but the included resources hash to {obtained_digest}"
        )

    return manifest.Manifest(model_name, items, serialization)


class Payload:
    """In-toto payload used to represent a model for signing.

    This payload represents all the object (files, shards, etc.) of the model
    paired with their hashes. It can be seen as a serialization of a manifest.
    The hashes are all recorded under the predicate, given that for the subject
    we are limited on what hashes we can use
    (https://github.com/sigstore/sigstore-python/issues/1018). Each hash follows
    the format of a ResourceDescriptor: is an object containing a name for the
    object, the hashing algorithm, and the digest value. These are recorded in
    the predicate, as part of the `"resources"` list.

    The subject is a name for the model (taken from the model's directory) and a
    global digest over all the computed digests. This is SHA256 computed over
    all the digests, in the order they show up in the predicate (we canonicalize
    this to be in alphabetical order). This digest can be used to refer to the
    model from other metadata documents without having to carry the entire set
    of resource descriptors around.

    To ensure backwards compatibility, the predicate contains a
    `"serialization"` section which describes the method used to serialize a
    model to the manifest used to generate this payload. The section includes a
    method name and a list of all relevant values needed to recompute the
    serialization.

    Future extensions to the model signature (e.g., incorporating model cards,
    etc.) can be added as part of the predicate. For v1.0 of the predicate the
    only supported fields in the predicate are `"serialization"` and
    `"resources"`. Any other field should be ignored by verifiers adhering to
    v1.0 version.

    Example:
    ```json
    {
      "_type": "https://in-toto.io/Statement/v1",
      "subject": [
        {
          "name": "sample_model",
          "digest": {
            "sha256": "143cc6..."
          }
        }
      ],
      "predicateType": "https://model_signing/signature/v1.0",
      "predicate": {
        "serialization": {
          "method": "files",
          "hash_type": "sha256",
          "allow_symlinks": true
        },
        "resources": [
          {
            "algorithm": "sha256",
            "digest": "fdd892...",
            "name": "d0/f00"
          },
          {
            "algorithm": "sha256",
            "digest": "e16940...",
            "name": "d0/f01"
          },
          {
            "algorithm": "sha256",
            "digest": "407822...",
            "name": "d0/f02"
          },
          ...
          {
            "algorithm": "sha256",
            "digest": "912bcf...",
            "name": "f3"
          }
        ]
      }
    }
    ```
    """

    def __init__(self, manifest: manifest.Manifest):
        """Builds an instance of this in-toto payload.

        Args:
            manifest: the manifest to convert to signing payload.
        """
        hasher = memory.SHA256()
        resources = []
        for descriptor in manifest.resource_descriptors():
            hasher.update(descriptor.digest.digest_value)
            resources.append(
                {
                    "name": descriptor.identifier,
                    "algorithm": descriptor.digest.algorithm,
                    "digest": descriptor.digest.digest_hex,
                }
            )

        root_digest = {"sha256": hasher.compute().digest_hex}
        subject = statement.ResourceDescriptor(
            name=manifest.model_name, digest=root_digest
        ).pb

        predicate = {
            "serialization": manifest.serialization_type,
            "resources": resources,
            # other properties can go here
        }

        self.statement = statement.Statement(
            subjects=[subject],
            predicate_type=_PREDICATE_TYPE,
            predicate=predicate,
        )


class Signature(metaclass=abc.ABCMeta):
    """Signature class, wrapping a sigstore bundle.

    We only support sigstore bundle signature formats, but we need to have two
    separate classes for this given the need to support traditional signing as
    well as Sigstore one. One class wraps around `sigstore_models.Bundle` and
    the other around the bundle as defined by `sigstore_protobuf_specs`.
    """

    @abc.abstractmethod
    def write(self, path: pathlib.Path) -> None:
        """Writes the signature to disk, to the given path.

        Args:
            path: The path to write the signature to.
        """

    @classmethod
    @abc.abstractmethod
    def read(cls, path: pathlib.Path) -> Self:
        """Reads the signature from disk.

        Does not perform any signature verification, except what is needed to
        parse the signature file.

        Args:
            path: The path to read the signature from.

        Returns:
            An instance of the class which can be passed to a `Verifier` for
            signature and integrity verification.
        """


class Signer(metaclass=abc.ABCMeta):
    """Generic signer.

    Each signer may implement its own mechanism for managing the key material.
    """

    @abc.abstractmethod
    def sign(self, payload: Payload) -> Signature:
        """Signs the provided signing payload.

        Args:
            payload: The `Payload` instance that should be signed.

        Returns:
            A valid signature.
        """


class Verifier(metaclass=abc.ABCMeta):
    """Generic signature verifier.

    Every subclass of `Verifier` is paired with a subclass of `Signer`. This is
    to ensure that they support the same signature formats as well as have
    similar key materials.

    If the signature is valid, the payload is expanded to a `Manifest` instance
    which can then be used to check the model integrity.
    """

    def verify(self, signature: Signature) -> manifest.Manifest:
        """Verifies the signature.

        Args:
            signature: The signature to verify.

        Returns:
            A `manifest.Manifest` instance that represents the model.

        Raises:
            ValueError: Signature verification fails.
        """
        payload_type, payload = self._verify_signed_content(signature)

        if payload_type != _IN_TOTO_JSON_PAYLOAD_TYPE:
            raise ValueError(
                f"Expected DSSE payload {_IN_TOTO_JSON_PAYLOAD_TYPE}, "
                f"but got {payload_type}"
            )

        payload = json.loads(payload)

        if payload["_type"] != _IN_TOTO_STATEMENT_TYPE:
            raise ValueError(
                f"Expected in-toto {_IN_TOTO_STATEMENT_TYPE} payload, "
                f"but got {payload['_type']}"
            )

        return dsse_payload_to_manifest(payload)

    @abc.abstractmethod
    def _verify_signed_content(self, signature: Signature) -> tuple[str, bytes]:
        """Verifies the signed content and extract payload type and payload.

        Subclasses only need to implement this method.

        Args:
            signature: The signature to verify.

        Returns:
            A tuple containing the payload type and the payload (as a JSON
            object loaded to a dictionary).
        """
