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
from model_signing.serialization import fixtures_constants
from model_signing.serialization import itemized


# Load fixtures from serialization/fixtures.py
pytest_plugins = ("model_signing.serialization.fixtures",)


class TestFilesSerializer:

    def _hasher_factory(self, path: pathlib.Path) -> file.FileHasher:
        return file.FileHasher(path, memory.SHA256())

    def test_known_file(self, sample_model_file):
        serializer = itemized.FilesSerializer(self._hasher_factory)
        expected = [
            "3aab065c7181a173b5dd9e9d32a9f79923440b413be1e1ffcdba26a7365f719b"
        ]

        manifest = serializer.serialize(sample_model_file)
        digests = [d.digest_hex for d in manifest._digest_info.values()]

        assert digests == expected

    def test_file_manifest_unchanged_when_model_moved(self, sample_model_file):
        serializer = itemized.FilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_file)

        new_name = sample_model_file.with_name("new-file")
        new_file = sample_model_file.rename(new_name)
        new_manifest = serializer.serialize(new_file)

        assert manifest == new_manifest

    def test_file_manifest_changes_if_content_changes(self, sample_model_file):
        serializer = itemized.FilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_file)
        digests = set(
            digest.digest_hex for digest in manifest._digest_info.values()
        )

        sample_model_file.write_bytes(fixtures_constants.ANOTHER_MODEL_TEXT)
        new_manifest = serializer.serialize(sample_model_file)
        new_digests = set(
            digest.digest_hex for digest in new_manifest._digest_info.values()
        )

        assert manifest != new_manifest
        assert digests != new_digests
        assert len(digests) == len(new_digests)

    def test_directory_model_with_one_single_file(self, sample_model_file):
        serializer = itemized.FilesSerializer(self._hasher_factory)
        manifest_file = serializer.serialize(sample_model_file)
        digests_file = set(
            digest.digest_hex for digest in manifest_file._digest_info.values()
        )

        manifest = serializer.serialize(sample_model_file.parent)
        digests = set(
            digest.digest_hex for digest in manifest._digest_info.values()
        )

        assert manifest != manifest_file  # different paths
        assert digests == digests_file

    def test_known_folder(self, sample_model_folder):
        serializer = itemized.FilesSerializer(self._hasher_factory)
        # Long hashes, want to update easily, so pylint: disable=line-too-long
        expected_items = {
            "f0": "997b37cc51f1ca1c7a270466607e26847429cd7264c30148c1b9352e224083fc",
            "f1": "c88a04d48353133fb065ba2c8ab369abab21395b9526aa20373ad828915fa7ae",
            "f2": "700e3ba5065d8dd47e41fd928ea086670d628f891ba363be0ca3c31d20d7d719",
            "f3": "912bcf5ebdf44dc7b4085b07940e0a81d157fba24b276e73fd911121d4544c4a",
            "d0/f00": "fdd8925354242a7fd1515e79534317b800015607a609cd306e0b4dcfe6c92249",
            "d0/f01": "e16940b5e44ce981150bda37c4ba95881a749a521b4a297c5cdf97bdcfe965e6",
            "d0/f02": "407822246ea8f9e26380842c3f4cd10d7b23e78f1fe7c74c293608682886a426",
            "d1/f10": "6a3b08b5df77c4d418ceee1ac136a9ad49fc7c41358b5e82c1176daccb21ff3f",
            "d1/f11": "a484b3d8ea5e99b75f9f123f9a42c882388693edc7d85d82ccba54834712cadf",
            "d1/f12": "8f577930f5f40c2c2133cb299d36f9527fde98c1608569017cae6b5bcd01abb3",
        }
        # Re-enable lint, so pylint: enable=line-too-long

        manifest = serializer.serialize(sample_model_folder)
        items = {
            str(path): digest.digest_hex
            for path, digest in manifest._digest_info.items()
        }

        assert items == expected_items

    def test_folder_model_hash_is_same_if_model_is_moved(
        self, sample_model_folder
    ):
        serializer = itemized.FilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        new_name = sample_model_folder.with_name("new-root")
        new_model = sample_model_folder.rename(new_name)
        new_manifest = serializer.serialize(new_model)

        assert manifest == new_manifest

    def test_folder_model_empty_folder_not_included(self, sample_model_folder):
        serializer = itemized.FilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]
        new_empty_dir = altered_dir / "empty"
        new_empty_dir.mkdir()
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest == new_manifest

    def test_folder_model_empty_file_gets_included(self, sample_model_folder):
        serializer = itemized.FilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]
        new_empty_file = altered_dir / "empty"
        new_empty_file.write_text("")
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest != new_manifest
        assert len(new_manifest._digest_info) == len(manifest._digest_info) + 1
        for path, digest in manifest._digest_info.items():
            assert new_manifest._digest_info[path] == digest

    def test_folder_model_rename_file_only_changes_path_part(
        self, sample_model_folder
    ):
        serializer = itemized.FilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]
        files = [f for f in altered_dir.iterdir() if f.is_file()]
        file_to_rename = files[0]
        old_name = file_to_rename.relative_to(sample_model_folder)
        old_name = pathlib.PurePosixPath(old_name)  # canonicalize to Posix
        new_name = file_to_rename.with_name("new-file")
        file_to_rename.rename(new_name)
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest != new_manifest
        assert len(new_manifest._digest_info) == len(manifest._digest_info)
        for path, digest in new_manifest._digest_info.items():
            if path.name == "new-file":
                assert manifest._digest_info[old_name] == digest
            else:
                assert manifest._digest_info[path] == digest

    def test_folder_model_rename_dir_only_changes_path_part(
        self, sample_model_folder
    ):
        serializer = itemized.FilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        dir_to_rename = dirs[0]
        old_name = dir_to_rename.name
        new_name = dir_to_rename.with_name("new-dir")
        dir_to_rename.rename(new_name)
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest != new_manifest
        assert len(new_manifest._digest_info) == len(manifest._digest_info)
        for path, digest in new_manifest._digest_info.items():
            if "new-dir" in path.parts:
                parts = [
                    old_name if part == "new-dir" else part
                    for part in path.parts
                ]
                old = pathlib.PurePosixPath(*parts)
                assert manifest._digest_info[old] == digest
            else:
                assert manifest._digest_info[path] == digest

    def test_folder_model_replace_file_empty_folder(self, sample_model_folder):
        serializer = itemized.FilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]
        files = [f for f in altered_dir.iterdir() if f.is_file()]
        file_to_replace = files[0]
        file_to_replace.unlink()
        file_to_replace.mkdir()
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest != new_manifest
        assert len(new_manifest._digest_info) == len(manifest._digest_info) - 1
        for path, digest in new_manifest._digest_info.items():
            assert manifest._digest_info[path] == digest

    def test_folder_model_change_file(self, sample_model_folder):
        serializer = itemized.FilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]
        files = [f for f in altered_dir.iterdir() if f.is_file()]
        file_to_change = files[0]
        file_to_change.write_bytes(fixtures_constants.KNOWN_MODEL_TEXT)
        changed_entry = file_to_change.relative_to(sample_model_folder)
        changed_entry = pathlib.PurePosixPath(changed_entry)  # canonicalize
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest != new_manifest
        assert len(new_manifest._digest_info) == len(manifest._digest_info)
        for path, digest in new_manifest._digest_info.items():
            if path == changed_entry:
                assert manifest._digest_info[path] != digest
            else:
                assert manifest._digest_info[path] == digest

    def test_deep_folder(self, deep_model_folder):
        serializer = itemized.FilesSerializer(self._hasher_factory)
        # Long hashes, want to update easily, so pylint: disable=line-too-long
        expected_items = {
            "d0/d1/d2/d3/d4/f0": "6efa14bb03544fcb76045c55f25b9315b6eb5be2d8a85f703193a76b7874c6ff",
            "d0/d1/d2/d3/d4/f1": "a9bc149b70b9d325cd68d275d582cfdb98c0347d3ce54590aa6533368daed3d2",
            "d0/d1/d2/d3/d4/f2": "5f597e6a92d1324d9adbed43d527926d11d0131487baf315e65ae1ef3b1ca3c0",
            "d0/d1/d2/d3/d4/f3": "eaf677c35fec6b87889d9e4563d8bb65dcb9869ca0225697c9cc44cf49dca008",
        }
        # Re-enable lint, so pylint: enable=line-too-long

        manifest = serializer.serialize(deep_model_folder)
        items = {
            str(path): digest.digest_hex
            for path, digest in manifest._digest_info.items()
        }

        assert items == expected_items

    def test_empty_file(self, empty_model_file):
        serializer = itemized.FilesSerializer(self._hasher_factory)
        expected = [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ]

        manifest = serializer.serialize(empty_model_file)
        digests = [d.digest_hex for d in manifest._digest_info.values()]

        assert digests == expected

    def test_empty_folder(self, empty_model_folder):
        serializer = itemized.FilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(empty_model_folder)
        assert not manifest._digest_info

    def test_special_file(self, sample_model_folder):
        serializer = itemized.FilesSerializer(self._hasher_factory)

        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]
        pipe = altered_dir / "pipe"

        try:
            os.mkfifo(pipe)
        except AttributeError:
            # On Windows, `os.mkfifo` does not exist (it should not).
            return  # trivially pass the test

        with pytest.raises(
            ValueError, match="Cannot use .* as file or directory"
        ):
            serializer.serialize(sample_model_folder)

        with pytest.raises(
            ValueError, match="Cannot use .* as file or directory"
        ):
            serializer.serialize(pipe)

    def test_max_workers_does_not_change_digest(self, sample_model_folder):
        serializer1 = itemized.FilesSerializer(self._hasher_factory)
        serializer2 = itemized.FilesSerializer(
            self._hasher_factory, max_workers=1
        )
        serializer3 = itemized.FilesSerializer(
            self._hasher_factory, max_workers=3
        )

        manifest1 = serializer1.serialize(sample_model_folder)
        manifest2 = serializer2.serialize(sample_model_folder)
        manifest3 = serializer3.serialize(sample_model_folder)

        assert manifest1 == manifest2
        assert manifest1 == manifest3


class TestShardedFilesSerializer:

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
            path, memory.SHA256(), start=start, end=end, shard_size=8
        )

    def test_known_file(self, sample_model_file):
        serializer = itemized.ShardedFilesSerializer(self._hasher_factory)
        expected = [
            "3aab065c7181a173b5dd9e9d32a9f79923440b413be1e1ffcdba26a7365f719b"
        ]

        manifest = serializer.serialize(sample_model_file)
        digests = [d.digest_hex for d in manifest._digest_info.values()]

        assert digests == expected

    def test_file_manifest_unchanged_when_model_moved(self, sample_model_file):
        serializer = itemized.ShardedFilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_file)

        new_name = sample_model_file.with_name("new-file")
        new_file = sample_model_file.rename(new_name)
        new_manifest = serializer.serialize(new_file)

        assert manifest == new_manifest

    def test_file_manifest_changes_if_content_changes(self, sample_model_file):
        serializer = itemized.ShardedFilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_file)
        digests = set(
            digest.digest_hex for digest in manifest._digest_info.values()
        )

        sample_model_file.write_bytes(fixtures_constants.ANOTHER_MODEL_TEXT)
        new_manifest = serializer.serialize(sample_model_file)
        new_digests = set(
            digest.digest_hex for digest in new_manifest._digest_info.values()
        )

        assert manifest != new_manifest
        assert len(digests) == len(new_digests)
        assert digests != new_digests

    def test_directory_model_with_one_single_file(self, sample_model_file):
        serializer = itemized.ShardedFilesSerializer(self._hasher_factory)
        manifest_file = serializer.serialize(sample_model_file)
        digests_file = set(
            digest.digest_hex for digest in manifest_file._digest_info.values()
        )

        manifest = serializer.serialize(sample_model_file.parent)
        digests = set(
            digest.digest_hex for digest in manifest._digest_info.values()
        )

        assert manifest != manifest_file  # different paths
        assert digests == digests_file

    def test_known_folder(self, sample_model_folder):
        serializer = itemized.ShardedFilesSerializer(self._hasher_factory)
        # Long hashes, want to update easily, so pylint: disable=line-too-long
        expected_items = {
            (
                "f0",
                0,
                24,
            ): "997b37cc51f1ca1c7a270466607e26847429cd7264c30148c1b9352e224083fc",
            (
                "f1",
                0,
                24,
            ): "c88a04d48353133fb065ba2c8ab369abab21395b9526aa20373ad828915fa7ae",
            (
                "f2",
                0,
                24,
            ): "700e3ba5065d8dd47e41fd928ea086670d628f891ba363be0ca3c31d20d7d719",
            (
                "f3",
                0,
                24,
            ): "912bcf5ebdf44dc7b4085b07940e0a81d157fba24b276e73fd911121d4544c4a",
            (
                "d0/f00",
                0,
                23,
            ): "fdd8925354242a7fd1515e79534317b800015607a609cd306e0b4dcfe6c92249",
            (
                "d0/f01",
                0,
                23,
            ): "e16940b5e44ce981150bda37c4ba95881a749a521b4a297c5cdf97bdcfe965e6",
            (
                "d0/f02",
                0,
                23,
            ): "407822246ea8f9e26380842c3f4cd10d7b23e78f1fe7c74c293608682886a426",
            (
                "d1/f10",
                0,
                23,
            ): "6a3b08b5df77c4d418ceee1ac136a9ad49fc7c41358b5e82c1176daccb21ff3f",
            (
                "d1/f11",
                0,
                23,
            ): "a484b3d8ea5e99b75f9f123f9a42c882388693edc7d85d82ccba54834712cadf",
            (
                "d1/f12",
                0,
                23,
            ): "8f577930f5f40c2c2133cb299d36f9527fde98c1608569017cae6b5bcd01abb3",
        }
        # Re-enable lint, so pylint: enable=line-too-long

        manifest = serializer.serialize(sample_model_folder)
        items = {
            # convert to file path (relative to model) string and endpoints
            (str(shard[0]), shard[1], shard[2]): digest.digest_hex
            for shard, digest in manifest._digest_info.items()
        }

        assert items == expected_items

    def test_folder_model_hash_is_same_if_model_is_moved(
        self, sample_model_folder
    ):
        serializer = itemized.ShardedFilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        new_name = sample_model_folder.with_name("new-root")
        new_model = sample_model_folder.rename(new_name)
        new_manifest = serializer.serialize(new_model)

        assert manifest == new_manifest

    def test_folder_model_empty_folder_not_included(self, sample_model_folder):
        serializer = itemized.ShardedFilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]
        new_empty_dir = altered_dir / "empty"
        new_empty_dir.mkdir()
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest == new_manifest

    def test_folder_model_empty_file_not_included(self, sample_model_folder):
        serializer = itemized.ShardedFilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]
        new_empty_file = altered_dir / "empty"
        new_empty_file.write_text("")
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest == new_manifest

    def test_folder_model_rename_file_only_changes_path_part(
        self, sample_model_folder
    ):
        serializer = itemized.ShardedFilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]
        files = [f for f in altered_dir.iterdir() if f.is_file()]
        file_to_rename = files[0]
        old_name = file_to_rename.relative_to(sample_model_folder)
        old_name = pathlib.PurePosixPath(old_name)  # canonicalize to Posix
        new_name = file_to_rename.with_name("new-file")
        file_to_rename.rename(new_name)
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest != new_manifest
        assert len(new_manifest._digest_info) == len(manifest._digest_info)
        for shard, digest in new_manifest._digest_info.items():
            path, start, end = shard
            if path.name == "new-file":
                old_shard = (old_name, start, end)
                assert manifest._digest_info[old_shard] == digest
            else:
                assert manifest._digest_info[shard] == digest

    def test_folder_model_rename_dir_only_changes_path_part(
        self, sample_model_folder
    ):
        serializer = itemized.ShardedFilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        dir_to_rename = dirs[0]
        old_name = dir_to_rename.name
        new_name = dir_to_rename.with_name("new-dir")
        dir_to_rename.rename(new_name)
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest != new_manifest
        assert len(new_manifest._digest_info) == len(manifest._digest_info)
        for shard, digest in new_manifest._digest_info.items():
            path, start, end = shard
            if "new-dir" in path.parts:
                parts = [
                    old_name if part == "new-dir" else part
                    for part in path.parts
                ]
                old = (pathlib.PurePosixPath(*parts), start, end)
                assert manifest._digest_info[old] == digest
            else:
                assert manifest._digest_info[shard] == digest

    def test_folder_model_replace_file_empty_folder(self, sample_model_folder):
        serializer = itemized.ShardedFilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]
        files = [f for f in altered_dir.iterdir() if f.is_file()]
        file_to_replace = files[0]
        file_to_replace.unlink()
        file_to_replace.mkdir()
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest != new_manifest
        assert len(new_manifest._digest_info) == len(manifest._digest_info) - 1
        for path, digest in new_manifest._digest_info.items():
            assert manifest._digest_info[path] == digest

    def test_folder_model_change_file(self, sample_model_folder):
        serializer = itemized.ShardedFilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]
        files = [f for f in altered_dir.iterdir() if f.is_file()]
        file_to_change = files[0]
        file_to_change.write_bytes(fixtures_constants.KNOWN_MODEL_TEXT)
        changed_entry = file_to_change.relative_to(sample_model_folder)
        changed_entry = pathlib.PurePosixPath(changed_entry)  # canonicalize
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest != new_manifest
        assert len(new_manifest._digest_info) == len(manifest._digest_info)
        for shard, digest in new_manifest._digest_info.items():
            path, _, _ = shard
            if path == changed_entry:
                # Note that the file size changes
                assert manifest._digest_info[(path, 0, 23)] != digest
            else:
                assert manifest._digest_info[shard] == digest

    def test_deep_folder(self, deep_model_folder):
        serializer = itemized.ShardedFilesSerializer(self._hasher_factory)
        # Long hashes, want to update easily, so pylint: disable=line-too-long
        expected_items = {
            (
                "d0/d1/d2/d3/d4/f0",
                0,
                16,
            ): "6efa14bb03544fcb76045c55f25b9315b6eb5be2d8a85f703193a76b7874c6ff",
            (
                "d0/d1/d2/d3/d4/f1",
                0,
                16,
            ): "a9bc149b70b9d325cd68d275d582cfdb98c0347d3ce54590aa6533368daed3d2",
            (
                "d0/d1/d2/d3/d4/f2",
                0,
                16,
            ): "5f597e6a92d1324d9adbed43d527926d11d0131487baf315e65ae1ef3b1ca3c0",
            (
                "d0/d1/d2/d3/d4/f3",
                0,
                16,
            ): "eaf677c35fec6b87889d9e4563d8bb65dcb9869ca0225697c9cc44cf49dca008",
        }
        # Re-enable lint, so pylint: enable=line-too-long

        manifest = serializer.serialize(deep_model_folder)
        items = {
            # convert to file path (relative to model) string and endpoints
            (str(shard[0]), shard[1], shard[2]): digest.digest_hex
            for shard, digest in manifest._digest_info.items()
        }

        assert items == expected_items

    def test_empty_file(self, empty_model_file):
        serializer = itemized.ShardedFilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(empty_model_file)
        assert not manifest._digest_info

    def test_empty_folder(self, empty_model_folder):
        serializer = itemized.ShardedFilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(empty_model_folder)
        assert not manifest._digest_info

    def test_special_file(self, sample_model_folder):
        serializer = itemized.ShardedFilesSerializer(self._hasher_factory)

        dirs = [d for d in sample_model_folder.iterdir() if d.is_dir()]
        altered_dir = dirs[0]
        pipe = altered_dir / "pipe"

        try:
            os.mkfifo(pipe)
        except AttributeError:
            # On Windows, `os.mkfifo` does not exist (it should not).
            return  # trivially pass the test

        with pytest.raises(
            ValueError, match="Cannot use .* as file or directory"
        ):
            serializer.serialize(sample_model_folder)

        with pytest.raises(
            ValueError, match="Cannot use .* as file or directory"
        ):
            serializer.serialize(pipe)

    def test_max_workers_does_not_change_digest(self, sample_model_folder):
        serializer1 = itemized.ShardedFilesSerializer(self._hasher_factory)
        serializer2 = itemized.ShardedFilesSerializer(
            self._hasher_factory, max_workers=1
        )
        serializer3 = itemized.ShardedFilesSerializer(
            self._hasher_factory, max_workers=3
        )

        manifest1 = serializer1.serialize(sample_model_folder)
        manifest2 = serializer2.serialize(sample_model_folder)
        manifest3 = serializer3.serialize(sample_model_folder)

        assert manifest1 == manifest2
        assert manifest1 == manifest3

    def test_known_folder_small_shards(self, sample_model_folder):
        serializer = itemized.ShardedFilesSerializer(
            self._hasher_factory_small_shards
        )
        # Long hashes, want to update easily, so pylint: disable=line-too-long
        expected_items = {
            (
                "f0",
                0,
                8,
            ): "a37010c994067764d86540bf479d93b4d0c3bb3955de7b61f951caf2fd0301b0",
            (
                "f0",
                8,
                16,
            ): "6ceb6f182993c238d6ce291d3f72f0de743d81faff85f4b038f4dffcc0eea50b",
            (
                "f0",
                16,
                24,
            ): "df42fcbd1023b80c82e869872ea01e1e1b0bbd60ab4c68c4054e7343ff0ce581",
            (
                "f1",
                0,
                8,
            ): "a37010c994067764d86540bf479d93b4d0c3bb3955de7b61f951caf2fd0301b0",
            (
                "f1",
                8,
                16,
            ): "be0c7e3632df2704636ebb173240d67568b7736a5e4c86c3e3cdee24e765fe92",
            (
                "f1",
                16,
                24,
            ): "df42fcbd1023b80c82e869872ea01e1e1b0bbd60ab4c68c4054e7343ff0ce581",
            (
                "f2",
                0,
                8,
            ): "a37010c994067764d86540bf479d93b4d0c3bb3955de7b61f951caf2fd0301b0",
            (
                "f2",
                8,
                16,
            ): "336bbabbb79a106f9eecbdeb3f2f6c4949735fdb307c1703dc41a65fbba4faf5",
            (
                "f2",
                16,
                24,
            ): "df42fcbd1023b80c82e869872ea01e1e1b0bbd60ab4c68c4054e7343ff0ce581",
            (
                "f3",
                0,
                8,
            ): "a37010c994067764d86540bf479d93b4d0c3bb3955de7b61f951caf2fd0301b0",
            (
                "f3",
                8,
                16,
            ): "2a40ca276886e04559e3babe13a9baf15fb2e2820befa5db7a0105449a55e77d",
            (
                "f3",
                16,
                24,
            ): "df42fcbd1023b80c82e869872ea01e1e1b0bbd60ab4c68c4054e7343ff0ce581",
            (
                "d0/f00",
                0,
                8,
            ): "a37010c994067764d86540bf479d93b4d0c3bb3955de7b61f951caf2fd0301b0",
            (
                "d0/f00",
                8,
                16,
            ): "03d5bb235fbf6771da18a650a7d01c1d6b85ada9de9cc62d27752a1c2a05548b",
            (
                "d0/f00",
                16,
                23,
            ): "003b089e217915b12ca9509b2f8a01be7cfe662ffadeb1cd3cf3f430c7b9773a",
            (
                "d0/f01",
                0,
                8,
            ): "a37010c994067764d86540bf479d93b4d0c3bb3955de7b61f951caf2fd0301b0",
            (
                "d0/f01",
                8,
                16,
            ): "819b976b5670c9c78a8bed6c2819757b5e2740db5e54e0a4da4b9bb1e5e80234",
            (
                "d0/f01",
                16,
                23,
            ): "003b089e217915b12ca9509b2f8a01be7cfe662ffadeb1cd3cf3f430c7b9773a",
            (
                "d0/f02",
                0,
                8,
            ): "a37010c994067764d86540bf479d93b4d0c3bb3955de7b61f951caf2fd0301b0",
            (
                "d0/f02",
                8,
                16,
            ): "635d7a05841e44a98e10ee9ac8346b8ed51653001a28d5c513a742c1408c7f33",
            (
                "d0/f02",
                16,
                23,
            ): "003b089e217915b12ca9509b2f8a01be7cfe662ffadeb1cd3cf3f430c7b9773a",
            (
                "d1/f10",
                0,
                8,
            ): "a37010c994067764d86540bf479d93b4d0c3bb3955de7b61f951caf2fd0301b0",
            (
                "d1/f10",
                8,
                16,
            ): "be0c2a2c271b113e22b02f495a1fa9b09bcc420b6ce969911827846519533811",
            (
                "d1/f10",
                16,
                23,
            ): "e6607ae1f591bd75d53b4a52bcd86ecf08643270814d20950ce4e762a99f773d",
            (
                "d1/f11",
                0,
                8,
            ): "a37010c994067764d86540bf479d93b4d0c3bb3955de7b61f951caf2fd0301b0",
            (
                "d1/f11",
                8,
                16,
            ): "3a9436f3f057b24fd7f830c6a230a08922b7b5d6f8255ae987bec4773a2d6152",
            (
                "d1/f11",
                16,
                23,
            ): "e6607ae1f591bd75d53b4a52bcd86ecf08643270814d20950ce4e762a99f773d",
            (
                "d1/f12",
                0,
                8,
            ): "a37010c994067764d86540bf479d93b4d0c3bb3955de7b61f951caf2fd0301b0",
            (
                "d1/f12",
                8,
                16,
            ): "93b0ae318b7ff95d0e9afdb975e1c6e7dca2d655d16a6801e0aa128bdfa65726",
            (
                "d1/f12",
                16,
                23,
            ): "e6607ae1f591bd75d53b4a52bcd86ecf08643270814d20950ce4e762a99f773d",
        }
        # Re-enable lint, so pylint: enable=line-too-long

        manifest = serializer.serialize(sample_model_folder)
        items = {
            # convert to file path (relative to model) string and endpoints
            (str(shard[0]), shard[1], shard[2]): digest.digest_hex
            for shard, digest in manifest._digest_info.items()
        }

        assert items == expected_items
