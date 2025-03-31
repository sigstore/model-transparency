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

"""Tests for file serializers.

NOTE: This test uses a goldens setup to compute digest of several test
models. If the golden tests are failing, regenerate the golden files with

  hatch test --update_goldens
"""

import os
import pathlib
from typing import cast

import pytest

from model_signing import manifest
from model_signing._hashing import file
from model_signing._hashing import memory
from model_signing._serialization import serialize_by_file
from tests import test_support


class TestManifestSerializer:
    def _hasher_factory(self, path: pathlib.Path) -> file.FileHasher:
        return file.SimpleFileHasher(path, memory.SHA256())

    @pytest.mark.parametrize("model_fixture_name", test_support.all_test_models)
    def test_known_models(self, request, model_fixture_name):
        # Set up variables (arrange)
        testdata_path = request.path.parent / "testdata"
        test_path = testdata_path / "serialize_by_file"
        test_class_path = test_path / "TestManifestSerializer"
        golden_path = test_class_path / model_fixture_name
        should_update = request.config.getoption("update_goldens")
        model = request.getfixturevalue(model_fixture_name)

        # Compute model manifest (act)
        serializer = serialize_by_file.ManifestSerializer(
            self._hasher_factory, allow_symlinks=True
        )
        manifest = serializer.serialize(model)
        items = test_support.extract_items_from_manifest(manifest)

        # Compare with golden, or write to golden (approximately "assert")
        if should_update:
            with open(golden_path, "w", encoding="utf-8") as f:
                for path, digest in sorted(items.items()):
                    f.write(f"{path}:{digest}\n")
        else:
            found_items: dict[str, str] = {}
            with open(golden_path, "r", encoding="utf-8") as f:
                for line in f:
                    path, digest = line.strip().split(":")
                    found_items[path] = digest

            assert items == found_items

    def test_file_manifest_unchanged_when_model_moved(self, sample_model_file):
        serializer = serialize_by_file.ManifestSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_file)

        new_name = sample_model_file.with_name("new-file")
        new_file = sample_model_file.rename(new_name)
        new_manifest = serializer.serialize(new_file)

        assert manifest == new_manifest

    def test_file_manifest_changes_if_content_changes(self, sample_model_file):
        serializer = serialize_by_file.ManifestSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_file)
        digests = set(test_support.extract_digests_from_manifest(manifest))

        sample_model_file.write_bytes(test_support.ANOTHER_MODEL_TEXT)
        new_manifest = serializer.serialize(sample_model_file)
        new_digests = set(
            test_support.extract_digests_from_manifest(new_manifest)
        )

        assert manifest != new_manifest
        assert digests != new_digests
        assert len(digests) == len(new_digests)

    def test_directory_model_with_only_known_file(self, sample_model_file):
        serializer = serialize_by_file.ManifestSerializer(self._hasher_factory)
        manifest_file = serializer.serialize(sample_model_file)
        digests_file = set(
            test_support.extract_digests_from_manifest(manifest_file)
        )

        manifest = serializer.serialize(sample_model_file.parent)
        digests = set(test_support.extract_digests_from_manifest(manifest))

        assert manifest != manifest_file  # different paths
        assert digests == digests_file

    def test_folder_model_hash_is_same_if_model_is_moved(
        self, sample_model_folder
    ):
        serializer = serialize_by_file.ManifestSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        new_name = sample_model_folder.with_name("new-root")
        new_model = sample_model_folder.rename(new_name)
        new_manifest = serializer.serialize(new_model)

        assert manifest == new_manifest

    def test_folder_model_empty_folder_not_included(self, sample_model_folder):
        serializer = serialize_by_file.ManifestSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        altered_dir = test_support.get_first_directory(sample_model_folder)
        new_empty_dir = altered_dir / "empty"
        new_empty_dir.mkdir()
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest == new_manifest

    def test_folder_model_empty_file_gets_included(self, sample_model_folder):
        serializer = serialize_by_file.ManifestSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        altered_dir = test_support.get_first_directory(sample_model_folder)
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
        old_manifest: manifest.Manifest,
        new_manifest: manifest.Manifest,
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
        for key, digest in new_manifest._item_to_digest.items():
            path = cast(manifest.File, key).path
            if path.name == new_name:
                key = manifest.File(old_name)
            else:
                key = manifest.File(path)
            assert old_manifest._item_to_digest[key] == digest

    def test_folder_model_rename_file_only_changes_path_part(
        self, sample_model_folder
    ):
        serializer = serialize_by_file.ManifestSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        altered_dir = test_support.get_first_directory(sample_model_folder)
        file_to_rename = test_support.get_first_file(altered_dir)
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
        old_manifest: manifest.Manifest,
        new_manifest: manifest.Manifest,
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
        for key, digest in new_manifest._item_to_digest.items():
            path = cast(manifest.File, key).path
            if new_name in path.parts:
                parts = [
                    old_name if part == new_name else part
                    for part in path.parts
                ]
                old = pathlib.PurePosixPath(*parts)
                key = manifest.File(old)
                assert old_manifest._item_to_digest[key] == digest
            else:
                key = manifest.File(path)
                assert old_manifest._item_to_digest[key] == digest

    def test_folder_model_rename_dir_only_changes_path_part(
        self, sample_model_folder
    ):
        serializer = serialize_by_file.ManifestSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        dir_to_rename = test_support.get_first_directory(sample_model_folder)
        old_name = dir_to_rename.name
        new_name = dir_to_rename.with_name("new-dir")
        dir_to_rename.rename(new_name)
        new_manifest = serializer.serialize(sample_model_folder)

        self._check_manifests_match_except_on_renamed_dir(
            manifest, new_manifest, "new-dir", old_name
        )

    def test_folder_model_replace_file_empty_folder(self, sample_model_folder):
        serializer = serialize_by_file.ManifestSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        altered_dir = test_support.get_first_directory(sample_model_folder)
        file_to_replace = test_support.get_first_file(altered_dir)
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
        old_manifest: manifest.Manifest,
        new_manifest: manifest.Manifest,
        expected_mismatch_path: pathlib.PurePath,
    ):
        """Checks that the manifests match, except for given path."""
        assert old_manifest != new_manifest
        assert len(new_manifest._item_to_digest) == len(
            old_manifest._item_to_digest
        )
        for key, digest in new_manifest._item_to_digest.items():
            path = cast(manifest.File, key).path
            if path == expected_mismatch_path:
                assert old_manifest._item_to_digest[key] != digest
            else:
                assert old_manifest._item_to_digest[key] == digest

    def test_folder_model_change_file(self, sample_model_folder):
        serializer = serialize_by_file.ManifestSerializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        altered_dir = test_support.get_first_directory(sample_model_folder)
        file_to_change = test_support.get_first_file(altered_dir)
        file_to_change.write_bytes(test_support.KNOWN_MODEL_TEXT)
        changed_entry = file_to_change.relative_to(sample_model_folder)
        changed_entry = pathlib.PurePosixPath(changed_entry)  # canonicalize
        new_manifest = serializer.serialize(sample_model_folder)

        self._check_manifests_match_except_on_entry(
            manifest, new_manifest, changed_entry
        )

    def test_max_workers_does_not_change_digest(self, sample_model_folder):
        serializer1 = serialize_by_file.ManifestSerializer(self._hasher_factory)
        serializer2 = serialize_by_file.ManifestSerializer(
            self._hasher_factory, max_workers=1
        )
        serializer3 = serialize_by_file.ManifestSerializer(
            self._hasher_factory, max_workers=3
        )

        manifest1 = serializer1.serialize(sample_model_folder)
        manifest2 = serializer2.serialize(sample_model_folder)
        manifest3 = serializer3.serialize(sample_model_folder)

        assert manifest1 == manifest2
        assert manifest1 == manifest3

    def test_symlinks_disallowed_by_default(self, symlink_model_folder):
        serializer = serialize_by_file.ManifestSerializer(self._hasher_factory)
        with pytest.raises(
            ValueError, match="Cannot use '.+' because it is a symlink."
        ):
            _ = serializer.serialize(symlink_model_folder)

    def test_ignore_list_respects_directories(self, sample_model_folder):
        serializer = serialize_by_file.ManifestSerializer(self._hasher_factory)
        manifest1 = serializer.serialize(sample_model_folder)
        ignore_path = test_support.get_first_directory(sample_model_folder)
        ignored_file_count = test_support.count_files(ignore_path)
        manifest2 = serializer.serialize(
            sample_model_folder, ignore_paths=[ignore_path]
        )
        assert manifest1 != manifest2
        diff = len(manifest1._item_to_digest) - len(manifest2._item_to_digest)
        assert diff == ignored_file_count


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
