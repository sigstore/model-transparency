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

import pytest

from model_signing.hashing import file
from model_signing.hashing import memory
from model_signing.serializing import dfs


# some constants used throughout testing
_KNOWN_MODEL_TEXT: bytes = b"This is a simple model"
_ANOTHER_MODEL_TEXT: bytes = b"This is another simple model"


# Note: Don't make fixtures with global scope as we are altering the models!
@pytest.fixture
def sample_model_file(tmp_path_factory):
    file = tmp_path_factory.mktemp("model") / "file"
    file.write_bytes(_KNOWN_MODEL_TEXT)
    return file


@pytest.fixture
def empty_model_file(tmp_path_factory):
    file = tmp_path_factory.mktemp("model") / "file"
    file.write_bytes(b"")
    return file


@pytest.fixture
def sample_model_folder(tmp_path_factory):
    model_root = tmp_path_factory.mktemp("model") / "root"
    model_root.mkdir()

    for i in range(2):
        root_dir = model_root / f"d{i}"
        root_dir.mkdir()
        for j in range(3):
            dir_file = root_dir / f"f{i}{j}"
            dir_file.write_text(f"This is file f{i}{j} in d{i}.")

    for i in range(4):
        root_file = model_root / f"f{i}"
        root_file.write_text(f"This is file f{i} in root.")

    return model_root


@pytest.fixture
def empty_model_folder(tmp_path_factory):
    model_root = tmp_path_factory.mktemp("model") / "root"
    model_root.mkdir()
    return model_root


@pytest.fixture
def deep_model_folder(tmp_path_factory):
    model_root = tmp_path_factory.mktemp("model") / "root"
    model_root.mkdir()

    current = model_root
    for i in range(5):
        current = current / f"d{i}"
        current.mkdir()

    for i in range(4):
        file = current / f"f{i}"
        file.write_text(f"This is file f{i}.")

    return model_root


class TestDFSSerializer:

    def test_known_file(self, sample_model_file):
        file_hasher = file.FileHasher("unused", memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(sample_model_file)
        expected = (
            "3aab065c7181a173b5dd9e9d32a9f79923440b413be1e1ffcdba26a7365f719b"
        )
        assert manifest.digest.digest_hex == expected

    def test_file_hash_is_same_as_hash_of_content(self, sample_model_file):
        file_hasher = file.FileHasher("unused", memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(sample_model_file)
        digest = memory.SHA256(_KNOWN_MODEL_TEXT).compute()
        assert manifest.digest.digest_hex == digest.digest_hex

    def test_file_model_hash_is_same_if_model_is_moved(self, sample_model_file):
        file_hasher = file.FileHasher("unused", memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(sample_model_file)

        new_name = sample_model_file.with_name("new-file")
        new_file = sample_model_file.rename(new_name)
        new_manifest = serializer.serialize(new_file)

        assert manifest == new_manifest

    def test_file_model_hash_changes_if_content_changes(
        self, sample_model_file
    ):
        file_hasher = file.FileHasher("unused", memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(sample_model_file)

        sample_model_file.write_bytes(_ANOTHER_MODEL_TEXT)
        new_manifest = serializer.serialize(sample_model_file)

        assert manifest.digest.algorithm == new_manifest.digest.algorithm
        assert manifest.digest.digest_value != new_manifest.digest.digest_value

    def test_directory_model_with_only_known_file(self, sample_model_file):
        file_hasher = file.FileHasher("unused", memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)

        model = sample_model_file.parent
        manifest = serializer.serialize(model)

        expected = (
            "a0865eb7e299e3bca3951e24930c56dcf1533ecff63bda06a9be67906773c628"
        )
        assert manifest.digest.digest_hex == expected

        digest = memory.SHA256(_KNOWN_MODEL_TEXT).compute()
        assert manifest.digest.digest_hex != digest.digest_hex

    def test_known_folder(self, sample_model_folder):
        file_hasher = file.FileHasher("unused", memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(sample_model_folder)
        expected = (
            "310af4fc4c52bf63cd1687c67076ed3e56bc5480a1b151539e6c550506ae0301"
        )
        assert manifest.digest.digest_hex == expected

    def test_folder_model_hash_is_same_if_model_is_moved(
        self, sample_model_folder
    ):
        file_hasher = file.FileHasher("unused", memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(sample_model_folder)

        new_name = sample_model_folder.with_name("new-root")
        new_model = sample_model_folder.rename(new_name)
        new_manifest = serializer.serialize(new_model)

        assert manifest == new_manifest

    def test_empty_file(self, empty_model_file):
        file_hasher = file.FileHasher("unused", memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(empty_model_file)
        expected = (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert manifest.digest.digest_hex == expected

    def test_directory_model_with_only_empty_file(self, empty_model_file):
        file_hasher = file.FileHasher("unused", memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(empty_model_file)
        model = empty_model_file.parent
        manifest = serializer.serialize(model)
        expected = (
            "8a587b2129fdecfbea38d5152b626299f5994d9b99d36b321aea356f69b38c61"
        )
        assert manifest.digest.digest_hex == expected

    def test_empty_folder(self, empty_model_folder):
        file_hasher = file.FileHasher("unused", memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(empty_model_folder)
        expected = (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert manifest.digest.digest_hex == expected

    def test_empty_folder_hashes_the_same_as_empty_file(
        self, empty_model_file, empty_model_folder
    ):
        file_hasher = file.FileHasher("unused", memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        folder_manifest = serializer.serialize(empty_model_folder)
        file_manifest = serializer.serialize(empty_model_file)
        assert (
            folder_manifest.digest.digest_hex == file_manifest.digest.digest_hex
        )

    def test_folder_model_empty_entry(self, sample_model_folder):
        file_hasher = file.FileHasher("unused", memory.SHA256())
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
        file_hasher = file.FileHasher("unused", memory.SHA256())
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
        file_hasher = file.FileHasher("unused", memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest1 = serializer.serialize(sample_model_folder)

        # Alter first directory within the model
        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        dir_to_rename = dirs[0]

        new_name = dir_to_rename.with_name("new-dir")
        dir_to_rename.rename(new_name)

        manifest2 = serializer.serialize(sample_model_folder)
        assert manifest1.digest != manifest2.digest

    def test_folder_model_change_file(self, sample_model_folder):
        file_hasher = file.FileHasher("unused", memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest1 = serializer.serialize(sample_model_folder)

        # Alter first directory within the model
        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]

        # Alter first file in the altered_dir
        files = [f for f in altered_dir.iterdir() if f.is_file()]
        file_to_change = files[0]
        file_to_change.write_bytes(_KNOWN_MODEL_TEXT)

        manifest2 = serializer.serialize(sample_model_folder)
        assert manifest1.digest != manifest2.digest

    def test_deep_folder(self, deep_model_folder):
        file_hasher = file.FileHasher("unused", memory.SHA256())
        serializer = dfs.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(deep_model_folder)
        expected = (
            "36eed9389ebbbe15ac15d33c81dabb60ccb7c945ff641d78f59db9aa9dc47ac9"
        )
        assert manifest.digest.digest_hex == expected
