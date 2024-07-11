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

import os
import pathlib
import pytest

from model_signing.hashing import file
from model_signing.hashing import memory
from model_signing.serialization import dfs
from model_signing.serialization import fixtures_constants


# Load fixtures from serialization/fixtures.py
pytest_plugins = ("model_signing.serialization.fixtures",)

_UNUSED_PATH = pathlib.Path("unused")


class TestDFSSerializer:

    def test_known_file(self, sample_model_file):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(sample_model_file)
        expected = (
            "3aab065c7181a173b5dd9e9d32a9f79923440b413be1e1ffcdba26a7365f719b"
        )
        assert manifest.digest.digest_hex == expected

    def test_file_hash_is_same_as_hash_of_content(self, sample_model_file):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(sample_model_file)
        digest = memory.SHA256(fixtures_constants.KNOWN_MODEL_TEXT).compute()
        assert manifest.digest.digest_hex == digest.digest_hex

    def test_file_model_hash_is_same_if_model_is_moved(self, sample_model_file):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(sample_model_file)

        new_name = sample_model_file.with_name("new-file")
        new_file = sample_model_file.rename(new_name)
        new_manifest = serializer.serialize(new_file)

        assert manifest == new_manifest

    def test_file_model_hash_changes_if_content_changes(
        self, sample_model_file
    ):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(sample_model_file)

        sample_model_file.write_bytes(fixtures_constants.ANOTHER_MODEL_TEXT)
        new_manifest = serializer.serialize(sample_model_file)

        assert manifest.digest.algorithm == new_manifest.digest.algorithm
        assert manifest.digest.digest_value != new_manifest.digest.digest_value

    def test_directory_model_with_only_known_file(self, sample_model_file):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)

        model = sample_model_file.parent
        manifest = serializer.serialize(model)

        expected = (
            "a0865eb7e299e3bca3951e24930c56dcf1533ecff63bda06a9be67906773c628"
        )
        assert manifest.digest.digest_hex == expected

        digest = memory.SHA256(fixtures_constants.KNOWN_MODEL_TEXT).compute()
        assert manifest.digest.digest_hex != digest.digest_hex

    def test_known_folder(self, sample_model_folder):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(sample_model_folder)
        expected = (
            "310af4fc4c52bf63cd1687c67076ed3e56bc5480a1b151539e6c550506ae0301"
        )
        assert manifest.digest.digest_hex == expected

    def test_folder_model_hash_is_same_if_model_is_moved(
        self, sample_model_folder
    ):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(sample_model_folder)

        new_name = sample_model_folder.with_name("new-root")
        new_model = sample_model_folder.rename(new_name)
        new_manifest = serializer.serialize(new_model)

        assert manifest == new_manifest

    def test_empty_file(self, empty_model_file):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(empty_model_file)
        expected = (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert manifest.digest.digest_hex == expected

    def test_directory_model_with_only_empty_file(self, empty_model_file):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(empty_model_file)
        model = empty_model_file.parent
        manifest = serializer.serialize(model)
        expected = (
            "8a587b2129fdecfbea38d5152b626299f5994d9b99d36b321aea356f69b38c61"
        )
        assert manifest.digest.digest_hex == expected

    def test_empty_folder(self, empty_model_folder):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(empty_model_folder)
        expected = (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert manifest.digest.digest_hex == expected

    def test_empty_folder_hashes_the_same_as_empty_file(
        self, empty_model_file, empty_model_folder
    ):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        folder_manifest = serializer.serialize(empty_model_folder)
        file_manifest = serializer.serialize(empty_model_file)
        assert (
            folder_manifest.digest.digest_hex == file_manifest.digest.digest_hex
        )

    def test_folder_model_empty_entry(self, sample_model_folder):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)

        # Alter first directory within the model
        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]

        new_empty_dir = altered_dir / "empty"
        new_empty_dir.mkdir()
        manifest1 = serializer.serialize(sample_model_folder)

        new_empty_dir.rmdir()

        new_empty_file = altered_dir / "empty"
        new_empty_file.write_text("")
        manifest2 = serializer.serialize(sample_model_folder)

        assert manifest1.digest != manifest2.digest

    def test_folder_model_rename_file(self, sample_model_folder):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest1 = serializer.serialize(sample_model_folder)

        # Alter first directory within the model
        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]

        # Alter first file in the altered_dir
        files = [f for f in altered_dir.iterdir() if f.is_file()]
        file_to_rename = files[0]

        new_name = file_to_rename.with_name("new-file")
        file_to_rename.rename(new_name)

        manifest2 = serializer.serialize(sample_model_folder)
        assert manifest1.digest != manifest2.digest

    def test_folder_model_rename_dir(self, sample_model_folder):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest1 = serializer.serialize(sample_model_folder)

        # Alter first directory within the model
        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        dir_to_rename = dirs[0]

        new_name = dir_to_rename.with_name("new-dir")
        dir_to_rename.rename(new_name)

        manifest2 = serializer.serialize(sample_model_folder)
        assert manifest1.digest != manifest2.digest

    def test_folder_model_replace_file_empty_folder(self, sample_model_folder):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest1 = serializer.serialize(sample_model_folder)

        # Alter first directory within the model
        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]

        # Replace first file in the altered_dir
        files = [f for f in altered_dir.iterdir() if f.is_file()]
        file_to_replace = files[0]
        file_to_replace.unlink()
        file_to_replace.mkdir()

        manifest2 = serializer.serialize(sample_model_folder)
        assert manifest1.digest != manifest2.digest

    def test_folder_model_change_file(self, sample_model_folder):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest1 = serializer.serialize(sample_model_folder)

        # Alter first directory within the model
        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]

        # Alter first file in the altered_dir
        files = [f for f in altered_dir.iterdir() if f.is_file()]
        file_to_change = files[0]
        file_to_change.write_bytes(fixtures_constants.KNOWN_MODEL_TEXT)

        manifest2 = serializer.serialize(sample_model_folder)
        assert manifest1.digest != manifest2.digest

    def test_deep_folder(self, deep_model_folder):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(deep_model_folder)
        expected = (
            "36eed9389ebbbe15ac15d33c81dabb60ccb7c945ff641d78f59db9aa9dc47ac9"
        )
        assert manifest.digest.digest_hex == expected

    def test_special_file(self, sample_model_folder):
        # Alter first directory within the model
        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]

        # Create a pipe in the altered_dir
        pipe = altered_dir / "pipe"

        try:
            os.mkfifo(pipe)
        except AttributeError:
            # On Windows, `os.mkfifo` does not exist (it should not).
            return  # trivially pass the test

        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)

        with pytest.raises(
            ValueError, match="Cannot use .* as file or directory"
        ):
            serializer.serialize(sample_model_folder)

        # Also do the same for the pipe itself
        with pytest.raises(
            ValueError, match="Cannot use .* as file or directory"
        ):
            serializer.serialize(pipe)


class TestShardedDFSSerializer:

    def _hasher_factory(
        self, path: pathlib.Path, start: int, end: int
    ) -> file.ShardedFileHasher:
        return file.ShardedFileHasher(
            path, memory.SHA256(), start=start, end=end
        )

    def _hasher_factory_small_shards(
        self, path: pathlib.Path, start: int, end: int
    ) -> file.ShardedFileHasher:
        return file.ShardedFileHasher(
            path, memory.SHA256(), start=start, end=end, shard_size=2
        )

    def test_known_file(self, sample_model_file):
        serializer = dfs.ShardedDFSSerializer(
            self._hasher_factory, memory.SHA256()
        )

        manifest = serializer.serialize(sample_model_file)

        expected = (
            "2ca48c47d5311a9b2f9305519cd5f927dcef09404fc32ef7886abe8f11450eff"
        )
        assert manifest.digest.digest_hex == expected

    def test_file_hash_is_not_same_as_hash_of_content(self, sample_model_file):
        serializer = dfs.ShardedDFSSerializer(
            self._hasher_factory, memory.SHA256()
        )

        manifest = serializer.serialize(sample_model_file)

        digest = memory.SHA256(fixtures_constants.KNOWN_MODEL_TEXT).compute()
        assert manifest.digest.digest_hex != digest.digest_hex

    def test_file_model_hash_is_same_if_model_is_moved(self, sample_model_file):
        serializer = dfs.ShardedDFSSerializer(
            self._hasher_factory, memory.SHA256()
        )
        manifest = serializer.serialize(sample_model_file)

        new_name = sample_model_file.with_name("new-file")
        new_file = sample_model_file.rename(new_name)
        new_manifest = serializer.serialize(new_file)

        assert manifest == new_manifest

    def test_file_model_hash_changes_if_content_changes(
        self, sample_model_file
    ):
        serializer = dfs.ShardedDFSSerializer(
            self._hasher_factory, memory.SHA256()
        )
        manifest = serializer.serialize(sample_model_file)

        sample_model_file.write_bytes(fixtures_constants.ANOTHER_MODEL_TEXT)
        new_manifest = serializer.serialize(sample_model_file)

        assert manifest.digest.algorithm == new_manifest.digest.algorithm
        assert manifest.digest.digest_value != new_manifest.digest.digest_value

    def test_directory_model_with_only_known_file(self, sample_model_file):
        serializer = dfs.ShardedDFSSerializer(
            self._hasher_factory, memory.SHA256()
        )

        model = sample_model_file.parent
        manifest = serializer.serialize(model)

        expected = (
            "c030412c4c9e7f46396b591b1b6c4a4e40c15d9b9ca0b3512af8b20f3219c07f"
        )
        assert manifest.digest.digest_hex == expected
        digest = memory.SHA256(fixtures_constants.KNOWN_MODEL_TEXT).compute()
        assert manifest.digest.digest_hex != digest.digest_hex

    def test_known_folder(self, sample_model_folder):
        serializer = dfs.ShardedDFSSerializer(
            self._hasher_factory, memory.SHA256()
        )

        manifest = serializer.serialize(sample_model_folder)

        expected = (
            "d22e0441cfa5ac2bc09715ddd88c802a7f97e29c93dc50f5498bab2954958ebb"
        )
        assert manifest.digest.digest_hex == expected

    def test_folder_model_hash_is_same_if_model_is_moved(
        self, sample_model_folder
    ):
        serializer = dfs.ShardedDFSSerializer(
            self._hasher_factory, memory.SHA256()
        )
        manifest = serializer.serialize(sample_model_folder)

        new_name = sample_model_folder.with_name("new-root")
        new_model = sample_model_folder.rename(new_name)
        new_manifest = serializer.serialize(new_model)

        assert manifest == new_manifest

    def test_empty_file(self, empty_model_file):
        serializer = dfs.ShardedDFSSerializer(
            self._hasher_factory, memory.SHA256()
        )

        manifest = serializer.serialize(empty_model_file)

        expected = (
            "5f2d126b0d3540c17481fdf724e31cf03b4436a2ebabaa1d2e94fe09831be64d"
        )
        assert manifest.digest.digest_hex == expected

    def test_directory_model_with_only_empty_file(self, empty_model_file):
        serializer = dfs.ShardedDFSSerializer(
            self._hasher_factory, memory.SHA256()
        )
        model = empty_model_file.parent

        manifest = serializer.serialize(model)

        expected = (
            "74e81d0062f0a0674014c2f0e4b79985d5015f98a64089e7106a44d32e9ff11f"
        )
        assert manifest.digest.digest_hex == expected

    def test_empty_folder(self, empty_model_folder):
        serializer = dfs.ShardedDFSSerializer(
            self._hasher_factory, memory.SHA256()
        )

        manifest = serializer.serialize(empty_model_folder)

        expected = (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert manifest.digest.digest_hex == expected

    def test_folder_model_empty_entry(self, sample_model_folder):
        serializer = dfs.ShardedDFSSerializer(
            self._hasher_factory, memory.SHA256()
        )

        # Alter first directory within the model
        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]

        new_empty_dir = altered_dir / "empty"
        new_empty_dir.mkdir()
        manifest1 = serializer.serialize(sample_model_folder)

        new_empty_dir.rmdir()

        new_empty_file = altered_dir / "empty"
        new_empty_file.write_text("")
        manifest2 = serializer.serialize(sample_model_folder)

        assert manifest1.digest != manifest2.digest

    def test_folder_model_rename_file(self, sample_model_folder):
        serializer = dfs.ShardedDFSSerializer(
            self._hasher_factory, memory.SHA256()
        )
        manifest1 = serializer.serialize(sample_model_folder)

        # Alter first directory within the model
        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]

        # Alter first file in the altered_dir
        files = [f for f in altered_dir.iterdir() if f.is_file()]
        file_to_rename = files[0]

        new_name = file_to_rename.with_name("new-file")
        file_to_rename.rename(new_name)

        manifest2 = serializer.serialize(sample_model_folder)
        assert manifest1.digest != manifest2.digest

    def test_folder_model_rename_dir(self, sample_model_folder):
        serializer = dfs.ShardedDFSSerializer(
            self._hasher_factory, memory.SHA256()
        )
        manifest1 = serializer.serialize(sample_model_folder)

        # Alter first directory within the model
        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        dir_to_rename = dirs[0]

        new_name = dir_to_rename.with_name("new-dir")
        dir_to_rename.rename(new_name)

        manifest2 = serializer.serialize(sample_model_folder)
        assert manifest1.digest != manifest2.digest

    def test_folder_model_replace_file_empty_folder(self, sample_model_folder):
        serializer = dfs.ShardedDFSSerializer(
            self._hasher_factory, memory.SHA256()
        )
        manifest1 = serializer.serialize(sample_model_folder)

        # Alter first directory within the model
        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]

        # Replace first file in the altered_dir
        files = [f for f in altered_dir.iterdir() if f.is_file()]
        file_to_replace = files[0]
        file_to_replace.unlink()
        file_to_replace.mkdir()

        manifest2 = serializer.serialize(sample_model_folder)
        assert manifest1.digest != manifest2.digest

    def test_folder_model_change_file(self, sample_model_folder):
        serializer = dfs.ShardedDFSSerializer(
            self._hasher_factory, memory.SHA256()
        )
        manifest1 = serializer.serialize(sample_model_folder)

        # Alter first directory within the model
        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]

        # Alter first file in the altered_dir
        files = [f for f in altered_dir.iterdir() if f.is_file()]
        file_to_change = files[0]
        file_to_change.write_bytes(fixtures_constants.KNOWN_MODEL_TEXT)

        manifest2 = serializer.serialize(sample_model_folder)
        assert manifest1.digest != manifest2.digest

    def test_deep_folder(self, deep_model_folder):
        serializer = dfs.ShardedDFSSerializer(
            self._hasher_factory, memory.SHA256()
        )

        manifest = serializer.serialize(deep_model_folder)

        expected = (
            "52fa3c459aec58bc5f9702c73cb3c6b8fd19e9342aa3e4db851e1bde69ab1727"
        )
        assert manifest.digest.digest_hex == expected

    def test_max_workers_does_not_change_digest(self, sample_model_folder):
        serializer1 = dfs.ShardedDFSSerializer(
            self._hasher_factory, memory.SHA256()
        )
        manifest1 = serializer1.serialize(sample_model_folder)

        serializer2 = dfs.ShardedDFSSerializer(
            self._hasher_factory, memory.SHA256(), max_workers=2
        )
        manifest2 = serializer2.serialize(sample_model_folder)

        assert manifest1 == manifest2

    def test_shard_size_changes_digests(self, sample_model_folder):
        serializer1 = dfs.ShardedDFSSerializer(
            self._hasher_factory, memory.SHA256()
        )
        manifest1 = serializer1.serialize(sample_model_folder)

        serializer2 = dfs.ShardedDFSSerializer(
            self._hasher_factory_small_shards, memory.SHA256()
        )
        manifest2 = serializer2.serialize(sample_model_folder)

        assert manifest1.digest.digest_value != manifest2.digest.digest_value

    def test_special_file(self, sample_model_folder):
        # Alter first directory within the model
        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]

        # Create a pipe in the altered_dir
        pipe = altered_dir / "pipe"

        try:
            os.mkfifo(pipe)
        except AttributeError:
            # On Windows, `os.mkfifo` does not exist (it should not).
            return  # trivially pass the test

        serializer = dfs.ShardedDFSSerializer(
            self._hasher_factory, memory.SHA256()
        )

        with pytest.raises(
            ValueError, match="Cannot use .* as file or directory"
        ):
            serializer.serialize(sample_model_folder)

        # Also do the same for the pipe itself
        with pytest.raises(
            ValueError, match="Cannot use .* as file or directory"
        ):
            serializer.serialize(pipe)


class TestUtilities:

    def test_check_file_or_directory_raises_on_pipes(self, sample_model_file):
        pipe = sample_model_file.with_name("pipe")

        try:
            os.mkfifo(pipe)
        except AttributeError:
            # On Windows, `os.mkfifo` does not exist (it should not).
            return  # trivially pass the test

        with pytest.raises(
            ValueError, match="Cannot use .* as file or directory"
        ):
            dfs.check_file_or_directory(pipe)

    def test_endpoints_exact(self):
        assert list(dfs.endpoints(2, 8)) == [2, 4, 6, 8]

    def test_endpoints_extra(self):
        assert list(dfs.endpoints(2, 9)) == [2, 4, 6, 8, 9]

    def test_endpoints_equal(self):
        assert list(dfs.endpoints(2, 2)) == [2]
