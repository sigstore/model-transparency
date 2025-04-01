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

A manifest pairs objects from the model (e.g., files, shards of files), with
their hashes. When signing the model we generate a manifest from serializing the
model (that is, computing the hashes for all the objects, according to the
specific serialization method used).

When verifying the integrity of the model, we extract a manifest from the
signature, after verifying the authenticity of the signature. Then, we serialize
the local model and compare the two manifests.

Comparing the manifests can be done by checking that everything matches, or, we
can only check partial object match. This is useful, for example, for the cases
where the original model contained files for multiple ML frameworks, but the
user only uses the model with one framework. This way, the user can verify the
integrity only for the files that are actually used.
"""

import abc
from collections.abc import Iterable, Iterator
import dataclasses
import pathlib
import sys

from typing_extensions import override

from model_signing._hashing import hashing


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


@dataclasses.dataclass(frozen=True, order=True)
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


class ManifestKey(metaclass=abc.ABCMeta):
    """An object that can be a key for an item in a manifest.

    We need to be able to convert the key to string when we serialize the
    manifest and to rebuild the object from the serialized representation when
    we deserialize the manifest from the signature.
    """

    @classmethod
    @abc.abstractmethod
    def from_str(cls, s: str) -> Self:
        """Builds a manifest key from the string representation.

        It is guaranteed that for any `key` of a derived class `C` and a (valid)
        string `s`, the following two round-trip properties hold:

        ```
        str(C.from_str(s)) == s
        C.from_str(str(key)) == key
        ```

        Raises:
            ValueError: if the string argument cannot be decoded correctly.
        """


@dataclasses.dataclass(frozen=True, order=True)
class File(ManifestKey):
    """A dataclass to hold information about a file as a manifest key.

    Attributes:
        path: The path to the file, relative to the model root.
    """

    path: pathlib.PurePath

    def __str__(self) -> str:
        return str(self.path)

    @classmethod
    @override
    def from_str(cls, s: str) -> Self:
        # Note that we always decode the string to a pure POSIX path
        return cls(pathlib.PurePosixPath(s))


@dataclasses.dataclass(frozen=True, order=True)
class Shard(ManifestKey):
    """A dataclass to hold information about a file shard as a manifest key.

    Attributes:
        path: The path to the file, relative to the model root.
        start: The start offset of the shard (included).
        end: The end offset of the shard (not included).
    """

    path: pathlib.PurePath
    start: int
    end: int

    def __str__(self) -> str:
        return f"{str(self.path)}:{self.start}:{self.end}"

    @classmethod
    @override
    def from_str(cls, s: str) -> Self:
        parts = s.split(":")
        if len(parts) != 3:
            raise ValueError(f"Expected 3 components separated by `:`, got {s}")

        path = pathlib.PurePosixPath(parts[0])
        start = int(parts[1])
        end = int(parts[2])

        return cls(path, start, end)


class ManifestItem(metaclass=abc.ABCMeta):
    """An individual object of a model, stored as an item in a manifest.

    For example, this could be a file, or a file shard. All file paths are
    relative to the model root, to allow moving or renaming the model, without
    invalidating the signature.

    The integrity of each `ManifestItem` can be verified individually and in
    parallel. If the item is backed by a file, we recompute the hash of the
    portion of the file that represents this item.

    Attributes:
        digest: The digest of the item. Use the `key` property to obtain a
          canonical unique representation for the item.
    """

    digest: hashing.Digest

    @property
    @abc.abstractmethod
    def key(self) -> ManifestKey:
        """A unique representation for the manifest item.

        Two items in the same manifest must not share the same `key`. The
        information contained in `key` should be sufficient to determine how to
        compute the item's digest.
        """


class FileManifestItem(ManifestItem):
    """A manifest item that records a filename path together with its digest.

    Note that the path component is a `pathlib.PurePath`, relative to the model.
    To ensure that the manifest is consistent across operating systems, we
    convert the path to a POSIX path.
    """

    def __init__(self, *, path: pathlib.PurePath, digest: hashing.Digest):
        """Builds a manifest item pairing a file with its digest.

        Args:
            path: The path to the file, relative to the model root.
            digest: The digest of the file.
        """
        # Note: we need to force a PurePosixPath to canonicalize the manifest.
        self._path = pathlib.PurePosixPath(path)
        self.digest = digest

    @property
    @override
    def key(self) -> ManifestKey:
        return File(self._path)


class ShardedFileManifestItem(ManifestItem):
    """A manifest item that records a file shard together with its digest.

    Note that the path component is a `pathlib.PurePath`, relative to the model.
    To ensure that the manifest is consistent across operating systems, we
    convert the path to a POSIX path.
    """

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
        # Note: we need to force a PurePosixPath to canonicalize the manifest.
        self._path = pathlib.PurePosixPath(path)
        self._start = start
        self._end = end
        self.digest = digest

    @property
    @override
    def key(self) -> ManifestKey:
        return Shard(self._path, self._start, self._end)


class Manifest:
    """Generic manifest file to represent a model."""

    def __init__(self, items: Iterable[ManifestItem]):
        """Builds a manifest from a collection of already hashed objects.

        Args:
            items: An iterable sequence of objects and their hashes.
        """
        self._item_to_digest = {item.key: item.digest for item in items}

    def __eq__(self, other: Self):
        return self._item_to_digest == other._item_to_digest

    def resource_descriptors(self) -> Iterator[ResourceDescriptor]:
        """Yields each resource from the manifest, one by one."""
        for item, digest in sorted(self._item_to_digest.items()):
            yield ResourceDescriptor(identifier=str(item), digest=digest)
