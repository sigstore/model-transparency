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
from model_signing.manifest import manifest
from model_signing.serialization import fixtures_constants
from model_signing.serialization import serialize_by_file


# Load fixtures from serialization/fixtures.py
pytest_plugins = ("model_signing.serialization.fixtures",)


_UNUSED_PATH = pathlib.Path("unused")


def _extract_digests_from_manifest(
    manifest: manifest.FileLevelManifest,
) -> list[str]:
    """Extracts the hex digest for every subject in a manifest.

    Used in multiple tests to check that we obtained the expected digests.
    """
    return [d.digest_hex for d in manifest._item_to_digest.values()]


def _extract_items_from_manifest(
    manifest: manifest.FileLevelManifest,
) -> dict[str, str]:
    """Builds a dictionary representation of the items in a manifest.

    Every item is mapped to its digest.

    Used in multiple tests to check that we obtained the expected manifest.
    """
    return {
        str(path): digest.digest_hex
        for path, digest in manifest._item_to_digest.items()
    }


def _get_first_directory(path: pathlib.Path) -> pathlib.Path:
    """Returns the first directory that is a children of path.

    It is assumed that there is always such a path.
    """
    return [d for d in path.iterdir() if d.is_dir()][0]


def _get_first_file(path: pathlib.Path) -> pathlib.Path:
    """Returns the first file that is a children of path.

    It is assumed that there is always such a path.
    """
    return [f for f in path.iterdir() if f.is_file()][0]


class TestDFSSerializer:

    def test_known_file(self, sample_model_file):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = serialize_by_file.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(sample_model_file)
        expected = (
            "3aab065c7181a173b5dd9e9d32a9f79923440b413be1e1ffcdba26a7365f719b"
        )
        assert manifest.digest.digest_hex == expected

    def test_file_hash_is_same_as_hash_of_content(self, sample_model_file):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = serialize_by_file.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(sample_model_file)
        digest = memory.SHA256(fixtures_constants.KNOWN_MODEL_TEXT).compute()
        assert manifest.digest.digest_hex == digest.digest_hex

    def test_file_model_hash_is_same_if_model_is_moved(self, sample_model_file):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = serialize_by_file.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(sample_model_file)

        new_name = sample_model_file.with_name("new-file")
        new_file = sample_model_file.rename(new_name)
        new_manifest = serializer.serialize(new_file)

        assert manifest == new_manifest

    def test_file_model_hash_changes_if_content_changes(
        self, sample_model_file
    ):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = serialize_by_file.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(sample_model_file)

        sample_model_file.write_bytes(fixtures_constants.ANOTHER_MODEL_TEXT)
        new_manifest = serializer.serialize(sample_model_file)

        assert manifest.digest.algorithm == new_manifest.digest.algorithm
        assert manifest.digest.digest_value != new_manifest.digest.digest_value

    def test_directory_model_with_only_known_file(self, sample_model_file):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = serialize_by_file.DFSSerializer(file_hasher, memory.SHA256)

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
        serializer = serialize_by_file.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(sample_model_folder)
        expected = (
            "310af4fc4c52bf63cd1687c67076ed3e56bc5480a1b151539e6c550506ae0301"
        )
        assert manifest.digest.digest_hex == expected

    def test_folder_model_hash_is_same_if_model_is_moved(
        self, sample_model_folder
    ):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = serialize_by_file.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(sample_model_folder)

        new_name = sample_model_folder.with_name("new-root")
        new_model = sample_model_folder.rename(new_name)
        new_manifest = serializer.serialize(new_model)

        assert manifest == new_manifest

    def test_empty_file(self, empty_model_file):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = serialize_by_file.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(empty_model_file)
        expected = (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert manifest.digest.digest_hex == expected

    def test_directory_model_with_only_empty_file(self, empty_model_file):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = serialize_by_file.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(empty_model_file)
        model = empty_model_file.parent
        manifest = serializer.serialize(model)
        expected = (
            "8a587b2129fdecfbea38d5152b626299f5994d9b99d36b321aea356f69b38c61"
        )
        assert manifest.digest.digest_hex == expected

    def test_empty_folder(self, empty_model_folder):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = serialize_by_file.DFSSerializer(file_hasher, memory.SHA256)
        manifest = serializer.serialize(empty_model_folder)
        expected = (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert manifest.digest.digest_hex == expected

    def test_empty_folder_hashes_the_same_as_empty_file(
        self, empty_model_file, empty_model_folder
    ):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = serialize_by_file.DFSSerializer(file_hasher, memory.SHA256)
        folder_manifest = serializer.serialize(empty_model_folder)
        file_manifest = serializer.serialize(empty_model_file)
        assert (
            folder_manifest.digest.digest_hex == file_manifest.digest.digest_hex
        )

    def test_folder_model_empty_entry(self, sample_model_folder):
        file_hasher = file.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        serializer = serialize_by_file.DFSSerializer(file_hasher, memory.SHA256)

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
        serializer = serialize_by_file.DFSSerializer(file_hasher, memory.SHA256)
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
        serializer = serialize_by_file.DFSSerializer(file_hasher, memory.SHA256)
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
        serializer = serialize_by_file.DFSSerializer(file_hasher, memory.SHA256)
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
        serializer = serialize_by_file.DFSSerializer(file_hasher, memory.SHA256)
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
        serializer = serialize_by_file.DFSSerializer(file_hasher, memory.SHA256)
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
        serializer = serialize_by_file.DFSSerializer(file_hasher, memory.SHA256)

        with pytest.raises(
            ValueError, match="Cannot use .* as file or directory"
        ):
            serializer.serialize(sample_model_folder)

        # Also do the same for the pipe itself
        with pytest.raises(
            ValueError, match="Cannot use .* as file or directory"
        ):
            serializer.serialize(pipe)


class TestFilesSerializer:

    def _hasher_factory(self, path: pathlib.Path) -> file.FileHasher:
        return file.SimpleFileHasher(path, memory.SHA256())

    def test_known_file(self, sample_model_file):
        serializer = serialize_by_file.FilesSerializer(self._hasher_factory)
        expected = [
            "3aab065c7181a173b5dd9e9d32a9f79923440b413be1e1ffcdba26a7365f719b"
        ]

        manifest = serializer.serialize(sample_model_file)
        digests = _extract_digests_from_manifest(manifest)

        assert digests == expected

    def test_file_manifest_unchanged_when_model_moved(self, sample_model_file):
        serializer = serialize_by_file.FilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_file)

        new_name = sample_model_file.with_name("new-file")
        new_file = sample_model_file.rename(new_name)
        new_manifest = serializer.serialize(new_file)

        assert manifest == new_manifest

    def test_file_manifest_changes_if_content_changes(self, sample_model_file):
        serializer = serialize_by_file.FilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_file)
        digests = set(_extract_digests_from_manifest(manifest))

        sample_model_file.write_bytes(fixtures_constants.ANOTHER_MODEL_TEXT)
        new_manifest = serializer.serialize(sample_model_file)
        new_digests = set(_extract_digests_from_manifest(new_manifest))

        assert manifest != new_manifest
        assert digests != new_digests
        assert len(digests) == len(new_digests)

    def test_directory_model_with_one_single_file(self, sample_model_file):
        serializer = serialize_by_file.FilesSerializer(self._hasher_factory)
        manifest_file = serializer.serialize(sample_model_file)
        digests_file = set(_extract_digests_from_manifest(manifest_file))

        manifest = serializer.serialize(sample_model_file.parent)
        digests = set(_extract_digests_from_manifest(manifest))

        assert manifest != manifest_file  # different paths
        assert digests == digests_file

    def test_known_folder(self, sample_model_folder):
        serializer = serialize_by_file.FilesSerializer(self._hasher_factory)
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
        items = _extract_items_from_manifest(manifest)

        assert items == expected_items

    def test_folder_model_hash_is_same_if_model_is_moved(
        self, sample_model_folder
    ):
        serializer = serialize_by_file.FilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        new_name = sample_model_folder.with_name("new-root")
        new_model = sample_model_folder.rename(new_name)
        new_manifest = serializer.serialize(new_model)

        assert manifest == new_manifest

    def test_folder_model_empty_folder_not_included(self, sample_model_folder):
        serializer = serialize_by_file.FilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        altered_dir = _get_first_directory(sample_model_folder)
        new_empty_dir = altered_dir / "empty"
        new_empty_dir.mkdir()
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest == new_manifest

    def test_folder_model_empty_file_gets_included(self, sample_model_folder):
        serializer = serialize_by_file.FilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        altered_dir = _get_first_directory(sample_model_folder)
        new_empty_file = altered_dir / "empty"
        new_empty_file.write_text("")
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest != new_manifest
        assert (
            len(new_manifest._item_to_digest)
            == len(manifest._item_to_digest) + 1
        )
        for path, digest in manifest._item_to_digest.items():
            assert new_manifest._item_to_digest[path] == digest

    def _check_manifests_match_except_on_renamed_file(
        self,
        old_manifest: manifest.FileLevelManifest,
        new_manifest: manifest.FileLevelManifest,
        new_name: str,
        old_name: pathlib.PurePath,
    ):
        """Checks that the manifests match, except on a renamed file.

        For the renamed file, we still want to match the digest of the old name.
        """
        assert old_manifest != new_manifest
        assert len(new_manifest._item_to_digest) == len(
            old_manifest._item_to_digest
        )
        for path, digest in new_manifest._item_to_digest.items():
            if path.name == new_name:
                assert old_manifest._item_to_digest[old_name] == digest
            else:
                assert old_manifest._item_to_digest[path] == digest

    def test_folder_model_rename_file_only_changes_path_part(
        self, sample_model_folder
    ):
        serializer = serialize_by_file.FilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        altered_dir = _get_first_directory(sample_model_folder)
        file_to_rename = _get_first_file(altered_dir)
        old_name = file_to_rename.relative_to(sample_model_folder)
        old_name = pathlib.PurePosixPath(old_name)  # canonicalize to Posix
        new_name = file_to_rename.with_name("new-file")
        file_to_rename.rename(new_name)
        new_manifest = serializer.serialize(sample_model_folder)

        self._check_manifests_match_except_on_renamed_file(
            manifest, new_manifest, "new-file", old_name
        )

    def _check_manifests_match_except_on_renamed_dir(
        self,
        old_manifest: manifest.FileLevelManifest,
        new_manifest: manifest.FileLevelManifest,
        new_name: str,
        old_name: str,
    ):
        """Checks that the manifests match, minus on paths under changed dir.

        For paths under the changed directory, we want to match the digest of
        the old path.
        """
        assert old_manifest != new_manifest
        assert len(new_manifest._item_to_digest) == len(
            old_manifest._item_to_digest
        )
        for path, digest in new_manifest._item_to_digest.items():
            if new_name in path.parts:
                parts = [
                    old_name if part == new_name else part
                    for part in path.parts
                ]
                old = pathlib.PurePosixPath(*parts)
                assert old_manifest._item_to_digest[old] == digest
            else:
                assert old_manifest._item_to_digest[path] == digest

    def test_folder_model_rename_dir_only_changes_path_part(
        self, sample_model_folder
    ):
        serializer = serialize_by_file.FilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        dir_to_rename = _get_first_directory(sample_model_folder)
        old_name = dir_to_rename.name
        new_name = dir_to_rename.with_name("new-dir")
        dir_to_rename.rename(new_name)
        new_manifest = serializer.serialize(sample_model_folder)

        self._check_manifests_match_except_on_renamed_dir(
            manifest, new_manifest, "new-dir", old_name
        )

    def test_folder_model_replace_file_empty_folder(self, sample_model_folder):
        serializer = serialize_by_file.FilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        altered_dir = _get_first_directory(sample_model_folder)
        file_to_replace = _get_first_file(altered_dir)
        file_to_replace.unlink()
        file_to_replace.mkdir()
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest != new_manifest
        assert (
            len(new_manifest._item_to_digest)
            == len(manifest._item_to_digest) - 1
        )
        for path, digest in new_manifest._item_to_digest.items():
            assert manifest._item_to_digest[path] == digest

    def _check_manifests_match_except_on_entry(
        self,
        old_manifest: manifest.FileLevelManifest,
        new_manifest: manifest.FileLevelManifest,
        expected_mismatch_path: pathlib.PurePath,
    ):
        """Checks that the manifests match, except for given path."""
        assert old_manifest != new_manifest
        assert len(new_manifest._item_to_digest) == len(
            old_manifest._item_to_digest
        )
        for path, digest in new_manifest._item_to_digest.items():
            if path == expected_mismatch_path:
                assert old_manifest._item_to_digest[path] != digest
            else:
                assert old_manifest._item_to_digest[path] == digest

    def test_folder_model_change_file(self, sample_model_folder):
        serializer = serialize_by_file.FilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        altered_dir = _get_first_directory(sample_model_folder)
        file_to_change = _get_first_file(altered_dir)
        file_to_change.write_bytes(fixtures_constants.KNOWN_MODEL_TEXT)
        changed_entry = file_to_change.relative_to(sample_model_folder)
        changed_entry = pathlib.PurePosixPath(changed_entry)  # canonicalize
        new_manifest = serializer.serialize(sample_model_folder)

        self._check_manifests_match_except_on_entry(
            manifest, new_manifest, changed_entry
        )

    def test_deep_folder(self, deep_model_folder):
        serializer = serialize_by_file.FilesSerializer(self._hasher_factory)
        # Long hashes, want to update easily, so pylint: disable=line-too-long
        expected_items = {
            "d0/d1/d2/d3/d4/f0": "6efa14bb03544fcb76045c55f25b9315b6eb5be2d8a85f703193a76b7874c6ff",
            "d0/d1/d2/d3/d4/f1": "a9bc149b70b9d325cd68d275d582cfdb98c0347d3ce54590aa6533368daed3d2",
            "d0/d1/d2/d3/d4/f2": "5f597e6a92d1324d9adbed43d527926d11d0131487baf315e65ae1ef3b1ca3c0",
            "d0/d1/d2/d3/d4/f3": "eaf677c35fec6b87889d9e4563d8bb65dcb9869ca0225697c9cc44cf49dca008",
        }
        # Re-enable lint, so pylint: enable=line-too-long

        manifest = serializer.serialize(deep_model_folder)
        items = _extract_items_from_manifest(manifest)

        assert items == expected_items

    def test_empty_file(self, empty_model_file):
        serializer = serialize_by_file.FilesSerializer(self._hasher_factory)
        expected = [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ]

        manifest = serializer.serialize(empty_model_file)
        digests = _extract_digests_from_manifest(manifest)

        assert digests == expected

    def test_empty_folder(self, empty_model_folder):
        serializer = serialize_by_file.FilesSerializer(self._hasher_factory)
        manifest = serializer.serialize(empty_model_folder)
        assert not manifest._item_to_digest

    def test_special_file(self, sample_model_folder):
        serializer = serialize_by_file.FilesSerializer(self._hasher_factory)

        altered_dir = _get_first_directory(sample_model_folder)
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
        serializer1 = serialize_by_file.FilesSerializer(self._hasher_factory)
        serializer2 = serialize_by_file.FilesSerializer(
            self._hasher_factory, max_workers=1
        )
        serializer3 = serialize_by_file.FilesSerializer(
            self._hasher_factory, max_workers=3
        )

        manifest1 = serializer1.serialize(sample_model_folder)
        manifest2 = serializer2.serialize(sample_model_folder)
        manifest3 = serializer3.serialize(sample_model_folder)

        assert manifest1 == manifest2
        assert manifest1 == manifest3


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
            serialize_by_file.check_file_or_directory(pipe)
