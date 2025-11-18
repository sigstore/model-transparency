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

"""Tests for incremental serialization."""

import pathlib

import pytest

from model_signing import manifest
from model_signing._hashing import hashing
from model_signing._hashing import io
from model_signing._hashing import memory
from model_signing._serialization import file
from model_signing._serialization import incremental
from tests import test_support


class TestIncrementalSerializer:
    @pytest.fixture
    def hasher_factory(self):
        """Provides a hasher factory for tests."""

        def factory(path: pathlib.Path) -> io.FileHasher:
            return io.SimpleFileHasher(path, memory.SHA256())

        return factory

    @pytest.fixture
    def file_serializer(self, hasher_factory):
        """Provides a file serializer for tests."""
        return file.Serializer(hasher_factory)

    @pytest.fixture
    def sharded_manifest(self):
        """Provides a shard-based manifest for tests."""
        shard_items = [
            manifest.ShardedFileManifestItem(
                path=pathlib.PurePosixPath("file.txt"),
                start=0,
                end=100,
                digest=hashing.Digest("sha256", b"fake_shard_digest"),
            )
        ]
        return manifest.Manifest(
            "model",
            shard_items,
            manifest._ShardSerialization("sha256", shard_size=100),
        )

    def test_no_changes_reuses_all_digests(
        self, sample_model_folder, hasher_factory, file_serializer
    ):
        # Create initial manifest
        existing_manifest = file_serializer.serialize(sample_model_folder)

        # Create incremental serializer
        inc_serializer = incremental.IncrementalSerializer(
            hasher_factory, existing_manifest
        )

        # Serialize incrementally (no changes)
        new_manifest = inc_serializer.serialize(sample_model_folder)

        # Manifests should be equal (all digests reused)
        assert new_manifest == existing_manifest

    def test_new_file_gets_hashed(
        self, sample_model_folder, hasher_factory, file_serializer
    ):
        # Create initial manifest
        existing_manifest = file_serializer.serialize(sample_model_folder)
        old_digests = set(
            test_support.extract_digests_from_manifest(existing_manifest)
        )

        # Add a new file
        altered_dir = test_support.get_first_directory(sample_model_folder)
        new_file = altered_dir / "new_file.txt"
        new_file.write_bytes(test_support.KNOWN_MODEL_TEXT)

        # Serialize incrementally
        inc_serializer = incremental.IncrementalSerializer(
            hasher_factory, existing_manifest
        )
        new_manifest = inc_serializer.serialize(sample_model_folder)

        # Should have one more digest
        new_digests = set(
            test_support.extract_digests_from_manifest(new_manifest)
        )
        assert len(new_digests) == len(old_digests) + 1
        assert old_digests.issubset(new_digests)

    def test_deleted_file_not_in_manifest(
        self, sample_model_folder, hasher_factory, file_serializer
    ):
        # Create initial manifest
        existing_manifest = file_serializer.serialize(sample_model_folder)
        old_digests = set(
            test_support.extract_digests_from_manifest(existing_manifest)
        )

        # Delete a file
        file_to_delete = test_support.get_first_file(sample_model_folder)
        file_to_delete.unlink()

        # Serialize incrementally
        inc_serializer = incremental.IncrementalSerializer(
            hasher_factory, existing_manifest
        )
        new_manifest = inc_serializer.serialize(sample_model_folder)

        # Should have one less digest
        new_digests = set(
            test_support.extract_digests_from_manifest(new_manifest)
        )
        assert len(new_digests) == len(old_digests) - 1
        assert new_digests.issubset(old_digests)

    def test_modified_file_with_files_to_hash(
        self, sample_model_folder, hasher_factory, file_serializer
    ):
        # Create initial manifest
        existing_manifest = file_serializer.serialize(sample_model_folder)
        old_digests = set(
            test_support.extract_digests_from_manifest(existing_manifest)
        )

        # Modify a file
        file_to_change = test_support.get_first_file(sample_model_folder)
        file_to_change.write_bytes(test_support.ANOTHER_MODEL_TEXT)

        # Serialize incrementally, specifying the changed file
        inc_serializer = incremental.IncrementalSerializer(
            hasher_factory, existing_manifest
        )
        new_manifest = inc_serializer.serialize(
            sample_model_folder, files_to_hash=[file_to_change]
        )

        # Should have same number of digests but one changed
        new_digests = set(
            test_support.extract_digests_from_manifest(new_manifest)
        )
        assert len(new_digests) == len(old_digests)
        assert new_digests != old_digests

    def test_manifest_unchanged_when_model_moved(
        self, sample_model_folder, hasher_factory, file_serializer
    ):
        # Create initial manifest
        existing_manifest = file_serializer.serialize(sample_model_folder)

        # Move the model
        new_name = sample_model_folder.with_name("moved_model")
        new_model = sample_model_folder.rename(new_name)

        # Serialize incrementally from new location
        inc_serializer = incremental.IncrementalSerializer(
            hasher_factory, existing_manifest
        )
        new_manifest = inc_serializer.serialize(new_model)

        # Manifests should be equal
        assert new_manifest == existing_manifest

    def test_empty_existing_manifest_hashes_all(
        self, sample_model_folder, hasher_factory, file_serializer
    ):
        # Create empty manifest
        empty_manifest = manifest.Manifest(
            "empty", [], manifest._FileSerialization("sha256")
        )

        # Serialize incrementally with empty existing manifest
        inc_serializer = incremental.IncrementalSerializer(
            hasher_factory, empty_manifest
        )
        new_manifest = inc_serializer.serialize(sample_model_folder)

        # Should hash all files (same as regular file serialization)
        expected_manifest = file_serializer.serialize(sample_model_folder)
        assert new_manifest == expected_manifest

    def test_sharded_manifest_rehashes_all(
        self,
        sample_model_folder,
        hasher_factory,
        file_serializer,
        sharded_manifest,
    ):
        # Serialize incrementally using the shard-based manifest
        inc_serializer = incremental.IncrementalSerializer(
            hasher_factory, sharded_manifest
        )
        new_manifest = inc_serializer.serialize(sample_model_folder)

        # Should rehash everything (file-based, not shard-based)
        expected_manifest = file_serializer.serialize(sample_model_folder)
        assert new_manifest == expected_manifest
