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

import hashlib
import pathlib

from model_signing import manifest
from model_signing._hashing import hashing
from model_signing._hashing import io as io_hashing
from model_signing._hashing import memory
from model_signing._serialization import incremental


class TestIncrementalSerializer:
    def test_no_changes_reuses_all_digests(self, tmp_path):
        """When no files change, all digests should be reused."""
        # Create a model with two files
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "file1.txt").write_text("content1")
        (model_dir / "file2.txt").write_text("content2")

        # Create an existing manifest (simulate previous signature)
        digest1 = hashing.Digest("sha256", b"digest1_bytes_here")
        digest2 = hashing.Digest("sha256", b"digest2_bytes_here")

        item1 = manifest.FileManifestItem(
            path=pathlib.PurePath("file1.txt"), digest=digest1
        )
        item2 = manifest.FileManifestItem(
            path=pathlib.PurePath("file2.txt"), digest=digest2
        )

        existing_manifest = manifest.Manifest(
            "model", [item1, item2], manifest._FileSerialization("sha256")
        )

        # Create incremental serializer
        def hasher_factory(path: pathlib.Path) -> io_hashing.FileHasher:
            return io_hashing.SimpleFileHasher(path, memory.SHA256())

        serializer = incremental.IncrementalSerializer(
            hasher_factory, existing_manifest
        )

        # Serialize the model incrementally
        new_manifest = serializer.serialize(model_dir)

        # Verify that digests were reused (not re-computed)
        descriptors = list(new_manifest.resource_descriptors())
        assert len(descriptors) == 2

        # Find each file's descriptor
        file1_desc = next(d for d in descriptors if d.identifier == "file1.txt")
        file2_desc = next(d for d in descriptors if d.identifier == "file2.txt")

        # Verify digests match the old manifest (were reused)
        assert file1_desc.digest.digest_value == b"digest1_bytes_here"
        assert file2_desc.digest.digest_value == b"digest2_bytes_here"

    def test_new_file_is_hashed(self, tmp_path):
        """When a new file is added, it should be hashed."""
        # Create a model with one existing file
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "file1.txt").write_text("content1")
        (model_dir / "file2.txt").write_text("content2")  # This is new

        # Create existing manifest with only file1
        digest1 = hashing.Digest("sha256", b"digest1_bytes_here")
        item1 = manifest.FileManifestItem(
            path=pathlib.PurePath("file1.txt"), digest=digest1
        )

        existing_manifest = manifest.Manifest(
            "model", [item1], manifest._FileSerialization("sha256")
        )

        # Create incremental serializer
        def hasher_factory(path: pathlib.Path) -> io_hashing.FileHasher:
            return io_hashing.SimpleFileHasher(path, memory.SHA256())

        serializer = incremental.IncrementalSerializer(
            hasher_factory, existing_manifest
        )

        # Serialize the model incrementally
        new_manifest = serializer.serialize(model_dir)

        # Verify we have both files
        descriptors = list(new_manifest.resource_descriptors())
        assert len(descriptors) == 2

        # file1 should have reused digest
        file1_desc = next(d for d in descriptors if d.identifier == "file1.txt")
        assert file1_desc.digest.digest_value == b"digest1_bytes_here"

        # file2 should have a new hash (not the fake digest)
        file2_desc = next(d for d in descriptors if d.identifier == "file2.txt")
        # It should be the actual SHA256 of "content2", not a reused digest
        assert file2_desc.digest.digest_value != b"digest1_bytes_here"
        assert file2_desc.digest.algorithm == "sha256"

    def test_deleted_file_not_in_manifest(self, tmp_path):
        """When a file is deleted, it should not appear in new manifest."""
        # Create a model with only one file
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "file1.txt").write_text("content1")

        # Create existing manifest with two files (file2 was deleted)
        digest1 = hashing.Digest("sha256", b"digest1_bytes_here")
        digest2 = hashing.Digest("sha256", b"digest2_bytes_here")

        item1 = manifest.FileManifestItem(
            path=pathlib.PurePath("file1.txt"), digest=digest1
        )
        item2 = manifest.FileManifestItem(
            path=pathlib.PurePath("file2.txt"), digest=digest2
        )

        existing_manifest = manifest.Manifest(
            "model", [item1, item2], manifest._FileSerialization("sha256")
        )

        # Create incremental serializer
        def hasher_factory(path: pathlib.Path) -> io_hashing.FileHasher:
            return io_hashing.SimpleFileHasher(path, memory.SHA256())

        serializer = incremental.IncrementalSerializer(
            hasher_factory, existing_manifest
        )

        # Serialize the model incrementally
        new_manifest = serializer.serialize(model_dir)

        # Verify only file1 is in the manifest
        descriptors = list(new_manifest.resource_descriptors())
        assert len(descriptors) == 1
        assert descriptors[0].identifier == "file1.txt"
        assert descriptors[0].digest.digest_value == b"digest1_bytes_here"

    def test_empty_existing_manifest_hashes_all(self, tmp_path):
        """With an empty existing manifest, all files should be hashed."""
        # Create a model with files
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "file1.txt").write_text("content1")
        (model_dir / "file2.txt").write_text("content2")

        # Create empty existing manifest
        existing_manifest = manifest.Manifest(
            "model", [], manifest._FileSerialization("sha256")
        )

        # Create incremental serializer
        def hasher_factory(path: pathlib.Path) -> io_hashing.FileHasher:
            return io_hashing.SimpleFileHasher(path, memory.SHA256())

        serializer = incremental.IncrementalSerializer(
            hasher_factory, existing_manifest
        )

        # Serialize the model incrementally
        new_manifest = serializer.serialize(model_dir)

        # Verify both files are hashed
        descriptors = list(new_manifest.resource_descriptors())
        assert len(descriptors) == 2

        # Both should have real hashes (not fake digests)
        for desc in descriptors:
            assert desc.digest.algorithm == "sha256"
            assert len(desc.digest.digest_value) == 32  # SHA256 is 32 bytes

    def test_modified_file_with_files_to_hash_parameter(self, tmp_path):
        """Test file is re-hashed when modified and in files_to_hash."""
        # Create a model with two files
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "file1.txt").write_text("content1")
        (model_dir / "README.md").write_text("old readme")

        # Create existing manifest with both files
        digest1 = hashing.Digest("sha256", b"digest1_bytes_here")
        digest_readme_old = hashing.Digest("sha256", b"old_readme_digest")

        item1 = manifest.FileManifestItem(
            path=pathlib.PurePath("file1.txt"), digest=digest1
        )
        item_readme = manifest.FileManifestItem(
            path=pathlib.PurePath("README.md"), digest=digest_readme_old
        )

        existing_manifest = manifest.Manifest(
            "model", [item1, item_readme], manifest._FileSerialization("sha256")
        )

        # User modifies README.md
        (model_dir / "README.md").write_text("new readme content")

        # Create incremental serializer
        def hasher_factory(path: pathlib.Path) -> io_hashing.FileHasher:
            return io_hashing.SimpleFileHasher(path, memory.SHA256())

        serializer = incremental.IncrementalSerializer(
            hasher_factory, existing_manifest
        )

        # Serialize with files_to_hash specifying the changed file
        new_manifest = serializer.serialize(
            model_dir,
            files_to_hash=[model_dir / "README.md"],  # Only this file changed
        )

        # Verify we have both files
        descriptors = list(new_manifest.resource_descriptors())
        assert len(descriptors) == 2

        # file1.txt should have reused digest
        file1_desc = next(d for d in descriptors if d.identifier == "file1.txt")
        assert file1_desc.digest.digest_value == b"digest1_bytes_here"

        # README.md should have a NEW hash (not the old one)
        readme_desc = next(
            d for d in descriptors if d.identifier == "README.md"
        )
        assert readme_desc.digest.digest_value != b"old_readme_digest"
        assert readme_desc.digest.algorithm == "sha256"
        assert len(readme_desc.digest.digest_value) == 32  # Real SHA256

    def test_deleted_file_in_files_to_hash_is_handled(self, tmp_path):
        """When a deleted file is in files_to_hash, it's safely ignored."""
        # Create a model with files
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "README.md").write_text("readme")
        (model_dir / "weights.bin").write_text("weights")

        # Create existing manifest with three files
        digest_readme = hashing.Digest("sha256", b"readme_digest")
        digest_old = hashing.Digest("sha256", b"old_file_digest")
        digest_weights = hashing.Digest("sha256", b"weights_digest")

        item_readme = manifest.FileManifestItem(
            path=pathlib.PurePath("README.md"), digest=digest_readme
        )
        item_old = manifest.FileManifestItem(
            path=pathlib.PurePath("old_file.txt"), digest=digest_old
        )
        item_weights = manifest.FileManifestItem(
            path=pathlib.PurePath("weights.bin"), digest=digest_weights
        )

        existing_manifest = manifest.Manifest(
            "model",
            [item_readme, item_old, item_weights],
            manifest._FileSerialization("sha256"),
        )

        # Create incremental serializer
        def hasher_factory(path: pathlib.Path) -> io_hashing.FileHasher:
            return io_hashing.SimpleFileHasher(path, memory.SHA256())

        serializer = incremental.IncrementalSerializer(
            hasher_factory, existing_manifest
        )

        # User specifies old_file.txt in files_to_hash (as git diff might)
        # even though the file was deleted
        deleted_file = model_dir / "old_file.txt"
        new_manifest = serializer.serialize(
            model_dir,
            files_to_hash=[deleted_file],  # Deleted file in the list
        )

        # Verify deleted file is NOT in new manifest
        descriptors = list(new_manifest.resource_descriptors())
        assert len(descriptors) == 2

        identifiers = [d.identifier for d in descriptors]
        assert "README.md" in identifiers
        assert "weights.bin" in identifiers
        assert "old_file.txt" not in identifiers  # Deleted file is gone

        # Other files should have reused digests
        readme_desc = next(
            d for d in descriptors if d.identifier == "README.md"
        )
        assert readme_desc.digest.digest_value == b"readme_digest"

        weights_desc = next(
            d for d in descriptors if d.identifier == "weights.bin"
        )
        assert weights_desc.digest.digest_value == b"weights_digest"

    def test_mixed_changes_with_files_to_hash(self, tmp_path):
        """Test realistic scenario: modify, add, delete files together."""
        # Initial state: three files
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "README.md").write_text("old readme")
        (model_dir / "weights.bin").write_text("weights")
        (model_dir / "new_config.json").write_text("new config")

        # Old manifest has README.md, old_file.txt, weights.bin
        digest_readme_old = hashing.Digest("sha256", b"old_readme_digest")
        digest_old_file = hashing.Digest("sha256", b"old_file_digest")
        digest_weights = hashing.Digest("sha256", b"weights_digest")

        item_readme = manifest.FileManifestItem(
            path=pathlib.PurePath("README.md"), digest=digest_readme_old
        )
        item_old = manifest.FileManifestItem(
            path=pathlib.PurePath("old_file.txt"), digest=digest_old_file
        )
        item_weights = manifest.FileManifestItem(
            path=pathlib.PurePath("weights.bin"), digest=digest_weights
        )

        existing_manifest = manifest.Manifest(
            "model",
            [item_readme, item_old, item_weights],
            manifest._FileSerialization("sha256"),
        )

        # User makes changes:
        # - Modifies README.md
        (model_dir / "README.md").write_text("new readme content")
        # - Deletes old_file.txt (already not on disk)
        # - Adds new_config.json (already on disk)
        # - Leaves weights.bin unchanged

        # Create incremental serializer
        def hasher_factory(path: pathlib.Path) -> io_hashing.FileHasher:
            return io_hashing.SimpleFileHasher(path, memory.SHA256())

        serializer = incremental.IncrementalSerializer(
            hasher_factory, existing_manifest
        )

        # Simulate git diff --name-only output
        files_to_hash = [
            model_dir / "README.md",  # Modified
            model_dir / "old_file.txt",  # Deleted
            model_dir / "new_config.json",  # Added
        ]

        new_manifest = serializer.serialize(
            model_dir, files_to_hash=files_to_hash
        )

        # Verify results
        descriptors = list(new_manifest.resource_descriptors())
        assert len(descriptors) == 3

        identifiers = [d.identifier for d in descriptors]
        assert "README.md" in identifiers  # Modified
        assert "new_config.json" in identifiers  # Added
        assert "weights.bin" in identifiers  # Unchanged
        assert "old_file.txt" not in identifiers  # Deleted

        # README.md should have NEW hash (was modified)
        readme_desc = next(
            d for d in descriptors if d.identifier == "README.md"
        )
        assert readme_desc.digest.digest_value != b"old_readme_digest"
        assert len(readme_desc.digest.digest_value) == 32

        # new_config.json should have NEW hash (was added)
        config_desc = next(
            d for d in descriptors if d.identifier == "new_config.json"
        )
        assert len(config_desc.digest.digest_value) == 32

        # weights.bin should have REUSED hash (unchanged)
        weights_desc = next(
            d for d in descriptors if d.identifier == "weights.bin"
        )
        assert weights_desc.digest.digest_value == b"weights_digest"

    def test_sharded_manifest_rehashes_all_files(self, tmp_path):
        """When existing manifest is shard-based, all files are rehashed."""
        # Create a model with two files
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "file1.txt").write_text("content1")
        (model_dir / "large_file.bin").write_bytes(b"large content here")

        # Create an existing shard-based manifest
        # (both files were sharded in the previous signature)
        shard1 = manifest.ShardedFileManifestItem(
            path=pathlib.PurePath("file1.txt"),
            start=0,
            end=100,
            digest=hashing.Digest("sha256", b"file1_shard_digest"),
        )
        shard2 = manifest.ShardedFileManifestItem(
            path=pathlib.PurePath("large_file.bin"),
            start=0,
            end=100,
            digest=hashing.Digest("sha256", b"large_shard1_digest"),
        )
        shard3 = manifest.ShardedFileManifestItem(
            path=pathlib.PurePath("large_file.bin"),
            start=100,
            end=200,
            digest=hashing.Digest("sha256", b"large_shard2_digest"),
        )

        existing_manifest = manifest.Manifest(
            "model",
            [shard1, shard2, shard3],
            manifest._ShardSerialization("sha256", shard_size=100),
        )

        # Create incremental serializer
        def hasher_factory(path: pathlib.Path) -> io_hashing.FileHasher:
            return io_hashing.SimpleFileHasher(path, memory.SHA256())

        serializer = incremental.IncrementalSerializer(
            hasher_factory, existing_manifest
        )

        # Serialize the model incrementally
        new_manifest = serializer.serialize(model_dir)

        # Verify results: both files should be re-hashed
        # (can't reuse shard digests for file-based serialization)
        descriptors = list(new_manifest.resource_descriptors())
        assert len(descriptors) == 2

        # Both files should have fresh digests computed
        file1_desc = next(d for d in descriptors if d.identifier == "file1.txt")
        # Should be real SHA256 of "content1", not the shard digest
        expected_digest1 = hashlib.sha256(b"content1").digest()
        assert file1_desc.digest.digest_value == expected_digest1
        assert file1_desc.digest.digest_value != b"file1_shard_digest"

        # large_file.bin should also be freshly hashed
        large_desc = next(
            d for d in descriptors if d.identifier == "large_file.bin"
        )
        # Should be real SHA256 of "large content here", not shard digests
        expected_digest2 = hashlib.sha256(b"large content here").digest()
        assert large_desc.digest.digest_value == expected_digest2
        assert large_desc.digest.digest_value != b"large_shard1_digest"
        assert large_desc.digest.digest_value != b"large_shard2_digest"
