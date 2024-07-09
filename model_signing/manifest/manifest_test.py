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

from model_signing.hashing import hashing
from model_signing.manifest import manifest


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
