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

"""An in-memory serialized representation of an ML model.

A manifest pairs objects from the model (e.g., files, shards of files), with
their hashes. When signing the model we first generate a manifest from
serializing the model using a configured serialization method (see
`model_signing.signing`).

When verifying the integrity of the model, after checking the authenticity of
the signature, we extract a manifest from it. Then, we serialize the local model
(the model being tested) and compare the two manifests.

The serialization method used during signing must match the one used during
verification. We can auto detect the method to use during verification from the
signature, but it is recommended to be explicit when possible.

Comparing the manifests can be done by checking that every item matches, both in
name and in associated hash.  In the future we will support partial object
matching. This is useful, for example, for the cases where the original model
contained files for multiple ML frameworks, but the user only uses the model
with one framework. This way, the user can verify the integrity only for the
files that are actually used.

This API should not be used directly, we don't guarantee that it is fully stable
at the moment.
"""

import abc
from collections.abc import Iterable, Iterator
import dataclasses
import pathlib
import sys
from typing import Any, Final

from typing_extensions import override

from model_signing._hashing import hashing


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


@dataclasses.dataclass(frozen=True, order=True)
class _ResourceDescriptor:
    """A description of any content from any `Manifest`.

    We aim this to be similar to in-toto's `ResourceDescriptor`. To support
    cases where in-toto cannot be directly used, we make this a dataclass that
    can be mapped to in-toto when needed, and used as its own otherwise.

    Not all fields from in-toto are specified at this moment. All fields here
    must be present, unlike in-toto, where all are optional.

    See github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md
    for the in-toto specification.

    Attributes:
        identifier: A string that uniquely identifies this object within the
        manifest. Depending on serialized format, users might require the
        identifier to be unique across all manifests stored in a system.
        Producers and consumers can agree on additional requirements (e.g.,
        several descriptors must have a common pattern for the identifier and
        the integrity of the model implies integrity of all these items,
        ignoring any other descriptor). Corresponds to `name`, `uri`, or
        `content` in in-toto specification.
        digest: One digest for the item. Note that unlike in-toto, we only have
          one digest for the item and it is always required.
    """

    identifier: str
    digest: hashing.Digest


class _ManifestKey(metaclass=abc.ABCMeta):
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
class _File(_ManifestKey):
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
class _Shard(_ManifestKey):
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
    def key(self) -> _ManifestKey:
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
    def key(self) -> _ManifestKey:
        return _File(self._path)


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
    def key(self) -> _ManifestKey:
        return _Shard(self._path, self._start, self._end)


class SerializationType(metaclass=abc.ABCMeta):
    """A description of the serialization process that generated the manifest.

    These should record all the parameters needed to ensure a reproducible
    serialization. These are used to build a manifest back from the signature in
    a backwards compatible way. We use these to determine what serialization to
    use when verifying a signature.
    """

    @property
    @abc.abstractmethod
    def serialization_parameters(self) -> dict[str, Any]:
        """The arguments of the serialization method."""

    @classmethod
    def from_args(cls, args: dict[str, Any]) -> Self:
        """Builds an instance of this class based on the dict representation.

        This is the reverse of `serialization_parameters`.

        Args:
            args: The arguments as a dictionary (equivalent to `**kwargs`).
        """
        serialization_type = args["method"]
        for subclass in [_FileSerialization, _ShardSerialization]:
            if serialization_type == subclass.method:
                return subclass._from_args(args)
        raise ValueError(f"Unknown serialization type {serialization_type}")

    @classmethod
    @abc.abstractmethod
    def _from_args(cls, args: dict[str, Any]) -> Self:
        """Performs the actual build from `from_dict`."""

    @abc.abstractmethod
    def new_item(self, name: str, digest: hashing.Digest) -> ManifestItem:
        """Builds a `ManifestItem` of the correct type.

        Each serialization type results in different types for the items in the
        manifest. This method parses the `name` of the item according to the
        serialization type to create the proper manifest item.

        Args:
            name: The name of the item, as shown in the manifest.
            digest: The digest of the item.
        """


class _FileSerialization(SerializationType):
    method: Final[str] = "files"

    def __init__(self, hash_type: str, allow_symlinks: bool = False):
        """Records the manifest serialization type for serialization by files.

        We only need to record the hashing engine used and whether symlinks are
        hashed or ignored.

        Args:
            hash_type: A string representation of the hash algorithm.
            allow_symlinks: Controls whether symbolic links are included.
        """
        self._hash_type = hash_type
        self._allow_symlinks = allow_symlinks

    @property
    @override
    def serialization_parameters(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "hash_type": self._hash_type,
            "allow_symlinks": self._allow_symlinks,
        }

    @classmethod
    @override
    def _from_args(cls, args: dict[str, Any]) -> Self:
        return cls(args["hash_type"], args["allow_symlinks"])

    @override
    def new_item(self, name: str, digest: hashing.Digest) -> ManifestItem:
        path = pathlib.PurePosixPath(name)
        return FileManifestItem(path=path, digest=digest)


class _ShardSerialization(SerializationType):
    method: Final[str] = "shards"

    def __init__(
        self, hash_type: str, shard_size: int, allow_symlinks: bool = False
    ):
        """Records the manifest serialization type for serialization by files.

        We need to record the hashing engine used and whether symlinks are
        hashed or ignored, just like for file serialization. We also need to
        record the shard size used to split the files, since different shard
        sizes results in different resources.

        Args:
            hash_type: A string representation of the hash algorithm.
            allow_symlinks: Controls whether symbolic links are included.
        """
        self._hash_type = hash_type
        self._allow_symlinks = allow_symlinks
        self._shard_size = shard_size

    @property
    @override
    def serialization_parameters(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "hash_type": self._hash_type,
            "shard_size": self._shard_size,
            "allow_symlinks": self._allow_symlinks,
        }

    @classmethod
    @override
    def _from_args(cls, args: dict[str, Any]) -> Self:
        return cls(
            args["hash_type"], args["shard_size"], args["allow_symlinks"]
        )

    @override
    def new_item(self, name: str, digest: hashing.Digest) -> ManifestItem:
        parts = name.split(":")
        if len(parts) != 3:
            raise ValueError(
                "Invalid resource name: expected 3 components separated by "
                f"`:`, got {name}"
            )

        path = pathlib.PurePosixPath(parts[0])
        start = int(parts[1])
        end = int(parts[2])
        return ShardedFileManifestItem(
            path=path, start=start, end=end, digest=digest
        )


class Manifest:
    """Generic manifest file to represent a model."""

    def __init__(
        self,
        model_name: str,
        items: Iterable[ManifestItem],
        serialization_type: SerializationType,
    ):
        """Builds a manifest from a collection of already hashed objects.

        Args:
            model_name: A name for the model that generated the manifest. This
              is the final component of the model path, and is only informative.
              See `model_name` property.
            items: An iterable sequence of objects and their hashes.
        """
        self._name = model_name
        self._item_to_digest = {item.key: item.digest for item in items}
        self._serialization_type = serialization_type

    def __eq__(self, other: Self):
        return self._item_to_digest == other._item_to_digest

    def resource_descriptors(self) -> Iterator[_ResourceDescriptor]:
        """Yields each resource from the manifest, one by one."""
        for item, digest in sorted(self._item_to_digest.items()):
            yield _ResourceDescriptor(identifier=str(item), digest=digest)

    @property
    def model_name(self) -> str:
        """The name of the model when serialized (final component of the path).

        This is only informative. Changing the name of the model should still
        result in the same digests after serialization, it must not invalidate
        signatures. As a result, two manifests with different model names but
        with the same resource descriptors will compare equal.
        """
        return self._name

    @property
    def serialization_type(self) -> dict[str, Any]:
        """The serialization (and arguments) used to build the manifest.

        This is needed to record the serialization method used to generate the
        manifest so that signature verification can use the same method.
        """
        return self._serialization_type.serialization_parameters
