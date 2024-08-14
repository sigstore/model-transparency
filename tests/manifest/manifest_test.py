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

import pathlib

import pytest

from model_signing.hashing import hashing
from model_signing.manifest import manifest


class TestDigestManifest:
    def test_manifest_has_just_one_resource_descriptor(self):
        digest = hashing.Digest("test", b"test_digest")
        manifest_file = manifest.DigestManifest(digest)

        descriptors = list(manifest_file.resource_descriptors())

        assert len(descriptors) == 1

    def test_manifest_has_the_correct_resource_descriptor(self):
        digest = hashing.Digest("test", b"test_digest")
        manifest_file = manifest.DigestManifest(digest)

        for descriptor in manifest_file.resource_descriptors():
            assert descriptor.identifier == ""
            assert descriptor.digest == digest


class TestFileLevelManifest:
    def test_insert_order_does_not_matter(self):
        path1 = pathlib.PurePath("file1")
        digest1 = hashing.Digest("test", b"abcd")
        item1 = manifest.FileManifestItem(path=path1, digest=digest1)

        path2 = pathlib.PurePath("file2")
        digest2 = hashing.Digest("test", b"efgh")
        item2 = manifest.FileManifestItem(path=path2, digest=digest2)

        manifest1 = manifest.FileLevelManifest([item1, item2])
        manifest2 = manifest.FileLevelManifest([item2, item1])

        assert manifest1 == manifest2

    @pytest.mark.parametrize("num_items", [1, 3, 5])
    def test_manifest_has_all_resource_descriptors(self, num_items):
        items: list[manifest.FileManifestItem] = []
        for i in range(num_items):
            path = pathlib.PurePath(f"file{i}")
            digest = hashing.Digest("test", b"hash{i}")
            item = manifest.FileManifestItem(path=path, digest=digest)
            items.append(item)
        manifest_file = manifest.FileLevelManifest(items)

        descriptors = list(manifest_file.resource_descriptors())

        assert len(descriptors) == num_items

    def test_manifest_has_the_correct_resource_descriptors(self):
        path1 = pathlib.PurePath("file1")
        digest1 = hashing.Digest("test", b"hash1")
        item1 = manifest.FileManifestItem(path=path1, digest=digest1)

        path2 = pathlib.PurePath("file2")
        digest2 = hashing.Digest("test", b"hash2")
        item2 = manifest.FileManifestItem(path=path2, digest=digest2)

        # Note order is reversed
        manifest_file = manifest.FileLevelManifest([item2, item1])
        descriptors = list(manifest_file.resource_descriptors())

        # But we expect the descriptors to be in order by file
        assert descriptors[0].identifier == "file1"
        assert descriptors[1].identifier == "file2"
        assert descriptors[0].digest.digest_value == b"hash1"
        assert descriptors[1].digest.digest_value == b"hash2"


class TestShard:
    def test_round_trip_from_shard(self):
        shard = manifest.Shard(pathlib.PurePosixPath("file"), 0, 42)
        shard_str = str(shard)
        assert manifest.Shard.from_str(shard_str) == shard

    def test_round_trip_from_string(self):
        shard_str = "file:0:42"
        shard = manifest.Shard.from_str(shard_str)
        assert str(shard) == shard_str

    def test_invalid_shard_str_too_few_components(self):
        shard_str = "file"

        with pytest.raises(ValueError, match="Expected 3 components"):
            manifest.Shard.from_str(shard_str)

    def test_invalid_shard_str_too_many_components(self):
        shard_str = "file:0:1:2"

        with pytest.raises(ValueError, match="Expected 3 components"):
            manifest.Shard.from_str(shard_str)

    def test_invalid_shard_bad_type_for_start_offset(self):
        shard_str = "file:zero:4"

        with pytest.raises(ValueError, match="invalid literal for int"):
            manifest.Shard.from_str(shard_str)

    def test_invalid_shard_bad_type_for_endart_offset(self):
        shard_str = "file:0:four"

        with pytest.raises(ValueError, match="invalid literal for int"):
            manifest.Shard.from_str(shard_str)


class TestShardLevelManifest:
    def test_insert_order_does_not_matter(self):
        path1 = pathlib.PurePath("file1")
        digest1 = hashing.Digest("test", b"abcd")
        item1 = manifest.ShardedFileManifestItem(
            path=path1, digest=digest1, start=0, end=4
        )

        path2 = pathlib.PurePath("file2")
        digest2 = hashing.Digest("test", b"efgh")
        item2 = manifest.ShardedFileManifestItem(
            path=path2, digest=digest2, start=0, end=4
        )

        manifest1 = manifest.ShardLevelManifest([item1, item2])
        manifest2 = manifest.ShardLevelManifest([item2, item1])

        assert manifest1 == manifest2

    def test_same_path_different_shards_gives_different_manifest(self):
        path = pathlib.PurePath("file")
        digest = hashing.Digest("test", b"abcd")

        item = manifest.ShardedFileManifestItem(
            path=path, digest=digest, start=0, end=2
        )
        manifest1 = manifest.ShardLevelManifest([item])

        item = manifest.ShardedFileManifestItem(
            path=path, digest=digest, start=2, end=4
        )
        manifest2 = manifest.ShardLevelManifest([item])

        assert manifest1 != manifest2

    @pytest.mark.parametrize("num_items", [1, 3, 5])
    def test_manifest_has_all_resource_descriptors(self, num_items):
        items: list[manifest.ShardedFileManifestItem] = []
        for i in range(num_items):
            path = pathlib.PurePath("file")
            digest = hashing.Digest("test", b"hash{i}")
            item = manifest.ShardedFileManifestItem(
                path=path, digest=digest, start=i, end=i + 2
            )
            items.append(item)
        manifest_file = manifest.ShardLevelManifest(items)

        descriptors = list(manifest_file.resource_descriptors())

        assert len(descriptors) == num_items

    def test_manifest_has_the_correct_resource_descriptors(self):
        path_to_file1 = pathlib.PurePath("file1")
        digest1 = hashing.Digest("test", b"hash1")
        item1 = manifest.ShardedFileManifestItem(
            path=path_to_file1, digest=digest1, start=0, end=4
        )

        # First file, but second shard
        digest2 = hashing.Digest("test", b"hash2")
        item2 = manifest.ShardedFileManifestItem(
            path=path_to_file1, digest=digest2, start=4, end=8
        )

        path_to_file2 = pathlib.PurePath("file2")
        digest3 = hashing.Digest("test", b"hash3")
        item3 = manifest.ShardedFileManifestItem(
            path=path_to_file2, digest=digest3, start=0, end=4
        )

        # Note order is not preserved (random permutation)
        manifest_file = manifest.ShardLevelManifest([item2, item3, item1])
        descriptors = list(manifest_file.resource_descriptors())

        # But we expect the descriptors to be in order by file shard
        assert descriptors[0].identifier == "file1:0:4"
        assert descriptors[1].identifier == "file1:4:8"
        assert descriptors[2].identifier == "file2:0:4"
        assert descriptors[0].digest.digest_value == b"hash1"
        assert descriptors[1].digest.digest_value == b"hash2"
        assert descriptors[2].digest.digest_value == b"hash3"
