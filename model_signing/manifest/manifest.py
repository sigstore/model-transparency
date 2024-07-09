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

"""Machinery for representing a serialized representation of an ML model.

When saving a model, or signing an existing one, we build a manifest from the
model (either by using a `serialization.Serializer` or building it from helper
methods that use precomputed values to reduce amount of I/O involved). This
manifest then gets signed and the signed manifest (or just signature) is stored
in a signature file determined from the model path and type. The signature is
loosely tied with the manifest (e.g., it could be a field in the manifest or it
could be a signature over a single digest).

When testing the integrity of a model, we start with the model path and model
type. From this, we extract the path to the signed manifest. Next step is to
verify the authenticity of the signature, after which we extract an in-memory
representation of the _trusted_ manifest. To verify the model in its integrity,
we run another `serialization.Serializer` instance to compute the _untrusted_
manifest of the model as we're seeing it. If these 2 manifests are conforming,
then the model integrity is maintained.

In the simplest case, we are working with `DigestManifest` objects. Here, the
two manifests are conforming iff the digests are the same. A more complex case
is when the manifest itemizes each model component (e.g., every file (or file
shard) is paired with its digest). The manifests would be conforming if every
file and digest matches. Alternatively, we could allow for file renames, and
check only the digests. Optionally, we can have arbitrary logic, saying that the
untrusted manifest must match only a subset of the trusted one: e.g., we could
have a model saved in multiple formats but with a single signature. At
verification time, only one format is used, so we only need to verify the
corresponding subset. We need to check that we still have a valid complete model
though.

In the future, we envision an API that would allow verification to be done in a
streaming fashion. As the model is loaded for inference, only the integrity of
the part that gets loaded would be verified, to not penalize inference hosts
when only a tiny subset of a large model is used. This also means that we can
add support for updating a manifest in a streaming fashion while a model is
trained (or post-training to update ancillary files -- requires re-signing).

All these alternative scenarios will be implemented by various subclasses of the
`Manifest` class defined here. Itemized manifests make use of `ItemizedManifest`
objects to represent only a part of the model that can be verified individually.
"""

import abc
import dataclasses
import pathlib
from typing import Iterable, Self

from model_signing.hashing import hashing


class Manifest(metaclass=abc.ABCMeta):
    """Generic manifest file to represent a model."""

    pass


@dataclasses.dataclass(frozen=True)
class DigestManifest(Manifest):
    """A manifest that is just a hash."""

    digest: hashing.Digest


class ItemizedManifest(Manifest):
    """A detailed manifest, recording integrity of every model component."""

    pass


class ManifestItem(metaclass=abc.ABCMeta):
    """An object of a model that can be stored in an `ItemizedManifest`.

    For example, this could be a file, or a file shard. All file paths are
    relative to the model root, to allow moving or renaming the model, without
    invalidating the signature.

    The integrity of each `ManifestItem` can be verified individually and in
    parallel. If the item is backed by a file, we recompute the hash of the
    portion of the file that represents this item.
    """

    pass


@dataclasses.dataclass(frozen=True)
class FileManifestItem(ManifestItem):
    """A manifest item that records a filename path together with its digest.

    Note that the path component is a `pathlib.PurePath`, relative to the model.
    """

    path: pathlib.PurePath
    digest: hashing.Digest


class FileLevelManifest(ItemizedManifest):
    """A detailed manifest, recording integrity of every model file."""

    def __init__(self, items: Iterable[FileManifestItem]):
        """Builds an itemized manifest from a collection of files.

        Rather than recording the items in a list, we use a dictionary, to allow
        efficient updates and retrieval of digests.
        """
        self._digest_info = {item.path: item.digest for item in items}

    def __eq__(self, other: Self):
        return self._digest_info == other._digest_info


@dataclasses.dataclass(frozen=True)
class ShardedFileManifestItem(ManifestItem):
    """A manifest item that records a file shard together with its digest."""

    path: pathlib.PurePath
    start: int
    end: int
    digest: hashing.Digest

    @property
    def input_tuple(self) -> tuple[pathlib.PurePath, int, int]:
        """Returns the triple that uniquely determines the manifest item."""
        return (self.path, self.start, self.end)


class ShardLevelManifest(ItemizedManifest):
    """A detailed manifest, recording integrity of every model file."""

    def __init__(self, items: Iterable[ShardedFileManifestItem]):
        """Builds an itemized manifest from a collection of files.

        Rather than recording the items in a list, we use a dictionary, to allow
        efficient updates and retrieval of digests.
        """
        self._digest_info = {item.input_tuple: item.digest for item in items}

    def __eq__(self, other: Self):
        return self._digest_info == other._digest_info
