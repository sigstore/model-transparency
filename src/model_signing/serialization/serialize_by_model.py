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

"""Model serializers that operated at model attr level granularity."""

import abc
import base64
from collections.abc import Callable, Iterable
import concurrent.futures
import collections
from typing import cast

from typing_extensions import override

from model_signing.hashing import model
from model_signing.hashing import hashing
from model_signing.manifest import manifest
from model_signing.serialization import serialization


def _build_header(*, entry_name: str) -> bytes:
    """Builds a header to encode a model with given name and type.

    Args:
        entry_name: The name of the entry to build the header for.

    Returns:
        A sequence of bytes that encodes all arguments as a sequence of UTF-8
        bytes. Each argument is separated by dots and the last byte is also a
        dot (so the model digest can be appended unambiguously).
    """
    encoded_type = 'collections.OrderedDict'.encode("utf-8")
    # Prevent confusion if name has a "." inside by encoding to base64.
    encoded_name = base64.b64encode(entry_name.encode("utf-8"))
    # Note: empty string at the end, to terminate header with a "."
    return b".".join([encoded_type, encoded_name, b""])


class ModelSerializer(serialization.Serializer):
    """Generic model serializer.

    Creates digests for every property of a model, possibly in parallel.

    Subclasses can then create a manifest with these digests, either listing
    them item by item, or combining everything into a single digest.
    """

    def __init__(
        self,
        model_hasher_factory: Callable[[collections.OrderedDict], model.ModelHasher],
        *,
        max_workers: int | None = None,
        allow_symlinks: bool = False,
    ):
        """Initializes an instance to serialize a model with this serializer.

        Args:
            model_hasher_factory: A callable to build the hash engine used to
              hash individual model attr.
            max_workers: Maximum number of workers to use in parallel. Default
              is to defer to the `concurrent.futures` library.
            allow_symlinks: Controls whether symbolic links are included. If a
              symlink is present but the flag is `False` (default) the
              serialization would raise an error.
        """
        self._hasher_factory = model_hasher_factory
        self._max_workers = max_workers
        self._allow_symlinks = allow_symlinks

    @override
    def serialize(
        self,
        model_state: collections.OrderedDict,
    ) -> manifest.Manifest:
        """Serializes the model given by the `model_state` argument.

        Args:
            model_state: The state of the model.
            ignore_models: The models to ignore during serialization. If a
              provided model is a directory, all children of the directory are
              ignored.

        Returns:
            The model's serialized `manifest.Manifest`

        Raises:
            ValueError: The model contains a symbolic link, but the serializer
              was not initialized with `allow_symlinks=True`.
        """
        models = []
        manifest_items = []
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self._max_workers
        ) as tpe:
            futures = [
                tpe.submit(self._compute_hash, model_state, model)
                for model in models
            ]
            for future in concurrent.futures.as_completed(futures):
                manifest_items.append(future.result())

        return self._build_manifest(manifest_items)

    def _compute_hash(
        self, model: collections.OrderedDict
    ) -> manifest.FileManifestItem:
        """Produces the manifest item of the attr given by `model`.

        Args:
            model: Dictionary representing an attribute of a model, that is
                currently transformed to a manifest item.

        Returns:
            The itemized manifest.
        """
        digest = self._hasher_factory(model).compute()
        return manifest.FileManifestItem(model=model, digest=digest)

    @abc.abstractmethod
    def _build_manifest(
        self, items: Iterable[manifest.FileManifestItem]
    ) -> manifest.Manifest:
        """Builds the manifest representing the serialization of the model."""
        pass


class ManifestSerializer(ModelSerializer):
    """Model serializer that produces an itemized manifest, at model level.

    Since the manifest lists each item individually, this will also enable
    support for incremental updates (to be added later).
    """

    @override
    def serialize(
        self,
        model_state: collections.OrderedDict,
        *,
        ignore_models: Iterable[collections.OrderedDict] = frozenset(),
    ) -> manifest.FileLevelManifest:
        """Serializes the model given by the `model_state` argument.

        The only reason for the override is to change the return type, to be
        more restrictive. This is to signal that the only manifests that can be
        returned are `manifest.FileLevelManifest` instances.

        Args:
            model_state: The model to the model.
            ignore_models: The models to ignore during serialization. If a
              provided model is a directory, all children of the directory are
              ignored.

        Returns:
            The model's serialized `manifest.FileLevelManifest`

        Raises:
            ValueError: The model contains a symbolic link, but the serializer
              was not initialized with `allow_symlinks=True`.
        """
        return cast(
            manifest.FileLevelManifest,
            super().serialize(model_state, ignore_models=ignore_models),
        )

    @override
    def _build_manifest(
        self, items: Iterable[manifest.FileManifestItem]
    ) -> manifest.FileLevelManifest:
        return manifest.FileLevelManifest(items)


class DigestSerializer(ModelSerializer):
    """Serializer for a model that performs a traversal of the model directory.

    This serializer produces a single hash for the entire model. If the model is
    a dict, the hash is the digest of the dict.

    Currently, this has a different initialization than `FilesSerializer`, but
    this will likely change in a subsequent change. Similarly, currently, this
    only supports one single worker, but this will change in the future.
    """

    def __init__(
        self,
        model_hasher: model.SimpleModelHasher,
        merge_hasher_factory: Callable[[], hashing.StreamingHashEngine],
        *,
        allow_symlinks: bool = False,
    ):
        """Initializes an instance to serialize a model with this serializer.

        Args:
            hasher: The hash engine used to hash the individual model attr.
            merge_hasher_factory: A callable that returns a
              `hashing.StreamingHashEngine` instance used to merge individual
              model digests to compute an aggregate digest.
            allow_symlinks: Controls whether symbolic links are included. If a
              symlink is present but the flag is `False` (default) the
              serialization would raise an error.
        """

        def _factory(model: collections.OrderedDict) -> model.SimpleModelHasher:
            model_hasher.set_model(model)
            return model_hasher

        super().__init__(_factory, max_workers=1, allow_symlinks=allow_symlinks)
        self._merge_hasher_factory = merge_hasher_factory

    @override
    def serialize(
        self,
        model_state: collections.OrderedDict,
        *,
        ignore_models: Iterable[collections.OrderedDict] = frozenset(),
    ) -> manifest.DigestManifest:
        """Serializes the model given by the `model_state` argument.

        The only reason for the override is to change the return type, to be
        more restrictive. This is to signal that the only manifests that can be
        returned are `manifest.DigestManifest` instances.

        Args:
            model_state: The model to the model.
            ignore_models: The models to ignore during serialization. If a
              provided model is a directory, all children of the directory are
              ignored.

        Returns:
            The model's serialized `manifest.DigestManifest`

        Raises:
            ValueError: The model contains a symbolic link, but the serializer
              was not initialized with `allow_symlinks=True`.
        """
        return cast(
            manifest.DigestManifest,
            super().serialize(model_state, ignore_models=ignore_models),
        )

    @override
    def _build_manifest(
        self, items: Iterable[manifest.ModelManifestItem]
    ) -> manifest.DigestManifest:
        # Note: we do several computations here to try and match the old
        # behavior but these would be simplified in the future. Since we are
        # defining the hashing behavior, we can freely change this.

        # If the model is just one dict, return the hash of the dict.
        items = list(items)
        if len(items) == 1 and not items[0].model.name:
            return manifest.DigestManifest(items[0].digest)

        # Otherwise, build a list of model attr and compute the digests.
        hasher = self._merge_hasher_factory()
        for i in items:
            hasher.update(_build_header(i.model_attr))
            hasher.update(i.digest)
        return manifest.DigestManifest(hasher.compute())
