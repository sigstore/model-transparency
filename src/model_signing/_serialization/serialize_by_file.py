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

"""Model serializers that operated at file level granularity."""

import abc
from collections.abc import Callable, Iterable
import concurrent.futures
import itertools
import pathlib
from typing import Optional, cast

from typing_extensions import override

from model_signing import manifest
from model_signing._hashing import file
from model_signing._serialization import serialization


class FilesSerializer(serialization.Serializer):
    """Generic file serializer.

    Traverses the model directory and creates digests for every file found,
    possibly in parallel.

    Subclasses can then create a manifest with these digests, either listing
    them item by item, or combining everything into a single digest.
    """

    def __init__(
        self,
        file_hasher_factory: Callable[[pathlib.Path], file.FileHasher],
        *,
        max_workers: Optional[int] = None,
        allow_symlinks: bool = False,
    ):
        """Initializes an instance to serialize a model with this serializer.

        Args:
            file_hasher_factory: A callable to build the hash engine used to
              hash individual files.
            max_workers: Maximum number of workers to use in parallel. Default
              is to defer to the `concurrent.futures` library.
            allow_symlinks: Controls whether symbolic links are included. If a
              symlink is present but the flag is `False` (default) the
              serialization would raise an error.
        """
        self._hasher_factory = file_hasher_factory
        self._max_workers = max_workers
        self._allow_symlinks = allow_symlinks

    @override
    def serialize(
        self,
        model_path: pathlib.Path,
        *,
        ignore_paths: Iterable[pathlib.Path] = frozenset(),
    ) -> manifest.Manifest:
        """Serializes the model given by the `model_path` argument.

        Args:
            model_path: The path to the model.
            ignore_paths: The paths to ignore during serialization. If a
              provided path is a directory, all children of the directory are
              ignored.

        Returns:
            The model's serialized `manifest.Manifest`

        Raises:
            ValueError: The model contains a symbolic link, but the serializer
              was not initialized with `allow_symlinks=True`.
        """
        paths = []
        # TODO: github.com/sigstore/model-transparency/issues/200 - When
        # Python3.12 is the minimum supported version, the glob can be replaced
        # with `pathlib.Path.walk` for a clearer interface, and some speed
        # improvement.
        for path in itertools.chain((model_path,), model_path.glob("**/*")):
            serialization.check_file_or_directory(
                path, allow_symlinks=self._allow_symlinks
            )
            if path.is_file() and not serialization.should_ignore(
                path, ignore_paths
            ):
                paths.append(path)

        manifest_items = []
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self._max_workers
        ) as tpe:
            futures = [
                tpe.submit(self._compute_hash, model_path, path)
                for path in paths
            ]
            for future in concurrent.futures.as_completed(futures):
                manifest_items.append(future.result())

        return self._build_manifest(manifest_items)

    def _compute_hash(
        self, model_path: pathlib.Path, path: pathlib.Path
    ) -> manifest.FileManifestItem:
        """Produces the manifest item of the file given by `path`.

        Args:
            model_path: The path to the model.
            path: Path to the file in the model, that is currently transformed
              to a manifest item.

        Returns:
            The itemized manifest.
        """
        relative_path = path.relative_to(model_path)
        digest = self._hasher_factory(path).compute()
        return manifest.FileManifestItem(path=relative_path, digest=digest)

    @abc.abstractmethod
    def _build_manifest(
        self, items: Iterable[manifest.FileManifestItem]
    ) -> manifest.Manifest:
        """Builds the manifest representing the serialization of the model."""
        pass


class ManifestSerializer(FilesSerializer):
    """Model serializer that produces an itemized manifest, at file level.

    Since the manifest lists each item individually, this will also enable
    support for incremental updates (to be added later).
    """

    @override
    def serialize(
        self,
        model_path: pathlib.Path,
        *,
        ignore_paths: Iterable[pathlib.Path] = frozenset(),
    ) -> manifest.Manifest:
        """Serializes the model given by the `model_path` argument.

        The only reason for the override is to change the return type, to be
        more restrictive. This is to signal that the only manifests that can be
        returned are `manifest.Manifest` instances.

        Args:
            model_path: The path to the model.
            ignore_paths: The paths to ignore during serialization. If a
              provided path is a directory, all children of the directory are
              ignored.

        Returns:
            The model's serialized `manifest.Manifest`

        Raises:
            ValueError: The model contains a symbolic link, but the serializer
              was not initialized with `allow_symlinks=True`.
        """
        return cast(
            manifest.Manifest,
            super().serialize(model_path, ignore_paths=ignore_paths),
        )

    @override
    def _build_manifest(
        self, items: Iterable[manifest.FileManifestItem]
    ) -> manifest.Manifest:
        return manifest.Manifest(items)
