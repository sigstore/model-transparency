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
methods that use precomputed values to reduce amount of I/O involved). This is
the manifest used for generating a signature of the model.

When testing the integrity of a model, we start with the model path and model
type. From this, we extract the path to the signed manifest. Next step is to
verify the authenticity of the signature, after which we extract an in-memory
representation of the _expected_ manifest. To verify the integrity of the model,
we run another `serialization.Serializer` instance to compute the _actual_
manifest of the model as we're seeing it. If these two manifests agree then the
model integrity is maintained.

In the simplest case, we are working with `DigestManifest` objects. Here, the
two manifests agree if and only if the digests are the same. A more complex case
is when the manifest itemizes each model component (e.g., every file (or file
shard) is paired with its digest). The manifests agree if every file and digest
matches. Alternatively, we could allow for file renames, and check only the
digests. Optionally, we can have arbitrary logic, saying that the actual
manifest (i.e., files of the model as they are on disk) must match only a subset
of the expected one: e.g., we could have a model saved in multiple formats but
with a single signature. At verification time, only one format is used, so we
only need to verify the corresponding subset. We need to check that we still
have a valid complete model though.

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
from collections.abc import Iterable, Iterator
import dataclasses
import pathlib
import sys

from typing_extensions import override

from model_signing.hashing import hashing


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


@dataclasses.dataclass(frozen=True)
class ResourceDescriptor:
    """A description of any content from any `Manifest`.

    We aim this to be similar to in-toto's `ResourceDescriptor`. To support
    cases where in-toto cannot be directly used, we make this a dataclass that
    can be mapped to in-toto when needed, and used as its own otherwise.

    Not all fields from in-toto are specified at this moment. All fields here
    must be present, unlike in-toto, where all are optional.

    See github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md
    for the in-toto specification.

    Attributes:
        identifier: A string that uniquely identifies this `ResourceDescriptor`
          within the manifest. Depending on serialized format, users might
          require the identifier to be unique across all manifests stored in a
          system. Producers and consumers can agree on additional requirements
          (e.g., several descriptors must have a common pattern for the
          identifier and the integrity of the model implies integrity of all
          these items, ignoring any other descriptor). Corresponds to `name`,
          `uri`, or `content` in in-toto specification.
        digest: One digest for the item. Note that unlike in-toto, we only have
          one digest for the item and it is always required.
    """

    identifier: str
    digest: hashing.Digest


class Manifest(metaclass=abc.ABCMeta):
    """Generic manifest file to represent a model."""

    @abc.abstractmethod
    def resource_descriptors(self) -> Iterator[ResourceDescriptor]:
        """Yields each resource from the manifest, one by one."""
        pass


@dataclasses.dataclass(frozen=True)
class DigestManifest(Manifest):
    """A manifest that is just a hash."""

    digest: hashing.Digest

    @override
    def resource_descriptors(self) -> Iterator[ResourceDescriptor]:
        """Yields each resource from the manifest, one by one.

        In this case, we have only one descriptor to return. Since model paths
        are already encoded in the digest, use "" for the identifier.
        Subclasses might record additional fields to have distinguishable human
        readable identifiers.
        """
        yield ResourceDescriptor(identifier="", digest=self.digest)


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


@dataclasses.dataclass
class FileManifestItem(ManifestItem):
    """A manifest item that records a filename path together with its digest.

    Note that the path component is a `pathlib.PurePath`, relative to the model.
    """

    path: pathlib.PurePath
    digest: hashing.Digest

    def __init__(self, *, path: pathlib.PurePath, digest: hashing.Digest):
        """Builds a manifest item pairing a file with its digest.

        Args:
            path: The path to the file, relative to the model root.
            digest: The digest of the file.
        """
        # Note: we need to force a PosixPath to canonicalize the manifest.
        self.path = pathlib.PurePosixPath(path)
        self.digest = digest


class FileLevelManifest(ItemizedManifest):
    """A detailed manifest, recording integrity of every model file."""

    def __init__(self, items: Iterable[FileManifestItem]):
        """Builds an itemized manifest from a collection of files.

        Rather than recording the items in a list, we use a dictionary, to allow
        efficient updates and retrieval of digests.
        """
        self._item_to_digest = {item.path: item.digest for item in items}

    def __eq__(self, other: Self):
        return self._item_to_digest == other._item_to_digest

    @override
    def resource_descriptors(self) -> Iterator[ResourceDescriptor]:
        """Yields each resource from the manifest, one by one.

        The items are returned in alphabetical order of the path.
        """
        for item, digest in sorted(self._item_to_digest.items()):
            yield ResourceDescriptor(identifier=str(item), digest=digest)


@dataclasses.dataclass(frozen=True, order=True)
class Shard:
    """A dataclass to hold information about a file shard.

    Attributes:
        path: The path to the file, relative to the model root.
        start: The start offset of the shard (included).
        end: The end offset of the shard (not included).
    """

    path: pathlib.PurePath
    start: int
    end: int

    def __str__(self) -> str:
        """Converts the item to a canonicalized string representation.

        The format is {path}:{start}:{end}, which should also be easy to decode.
        """
        return f"{str(self.path)}:{self.start}:{self.end}"

    @classmethod
    def from_str(cls, s: str) -> Self:
        """Builds a file shard from the string representation.

        It is guaranteed that for a shard `shard` and a (valid) string `s` the
        following two round-trip properties hold:

        ```
        str(Shard.from_str(s)) == s
        Shard.from_str(str(shard)) == shard
        ```

        Raises:
            ValueError: if the string argument does not represent a valid shard
            serialization (is not in the format `path:start:end`).
        """
        parts = s.split(":")
        if len(parts) != 3:
            raise ValueError(f"Expected 3 components separated by `:`, got {s}")

        path = pathlib.PurePosixPath(parts[0])
        start = int(parts[1])
        end = int(parts[2])

        return cls(path, start, end)


@dataclasses.dataclass
class ShardedFileManifestItem(ManifestItem):
    """A manifest item that records a file shard together with its digest."""

    path: pathlib.PurePath
    start: int
    end: int
    digest: hashing.Digest

    def __init__(
        self,
        *,
        path: pathlib.PurePath,
        start: int,
        end: int,
        digest: hashing.Digest,
    ):
        """Builds a manifest item pairing a file shard with its digest.

        Args:
            path: The path to the file, relative to the model root.
            start: The start offset of the shard (included).
            end: The end offset of the shard (not included).
            digest: The digest of the file shard.
        """
        # Note: we need to force a PosixPath to canonicalize the manifest
        self.path = pathlib.PurePosixPath(path)
        self.start = start
        self.end = end
        self.digest = digest

    @property
    def input_tuple(self) -> Shard:
        """Returns the triple that uniquely determines the manifest item."""
        return Shard(self.path, self.start, self.end)


class ShardLevelManifest(FileLevelManifest):
    """A detailed manifest, recording integrity of every model file."""

    def __init__(self, items: Iterable[ShardedFileManifestItem]):
        """Builds an itemized manifest from a collection of files.

        Rather than recording the items in a list, we use a dictionary, to allow
        efficient updates and retrieval of digests.
        """
        self._item_to_digest = {item.input_tuple: item.digest for item in items}

    @override
    def resource_descriptors(self) -> Iterator[ResourceDescriptor]:
        """Yields each resource from the manifest, one by one.

        The items are returned in the order given by the `Shard` dataclass
        (implicit ordering: by file, shard start offset and shard end offset, in
        order).
        """
        for item, digest in sorted(self._item_to_digest.items()):
            yield ResourceDescriptor(identifier=str(item), digest=digest)
