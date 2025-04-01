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

"""Tests for shard serializers.

NOTE: This test uses a golden setup to compute digest of several test
models. If the golden tests are failing, regenerate the golden files with

  hatch test --update_goldens
"""

import pathlib
from typing import cast

import pytest

from model_signing import manifest
from model_signing._hashing import file_hashing
from model_signing._hashing import memory
from model_signing._serialization import file_shard
from tests import test_support


def _extract_shard_items_from_manifest(
    manifest: manifest.Manifest,
) -> dict[manifest.ManifestKey, str]:
    """Builds a dictionary representation of the items in a manifest.

    Every item is mapped to its digest.

    Used in multiple tests to check that we obtained the expected manifest.
    """
    return {
        shard: digest.digest_hex
        for shard, digest in manifest._item_to_digest.items()
    }


def _parse_shard_and_digest(line: str) -> tuple[manifest.Shard, str]:
    """Reads a file shard and its digest from a line in the golden file.

    Args:
        line: The line to parse.

    Returns:
        The shard tuple and the digest corresponding to the line that was read.
    """
    path, start, end, digest = line.strip().split(":")
    shard = manifest.Shard(pathlib.PurePosixPath(path), int(start), int(end))
    return shard, digest


class TestSerializer:
    def _hasher_factory(
        self, path: pathlib.Path, start: int, end: int
    ) -> file_hashing.ShardedFileHasher:
        return file_hashing.ShardedFileHasher(
            path, memory.SHA256(), start=start, end=end
        )

    def _hasher_factory_small_shards(
        self, path: pathlib.Path, start: int, end: int
    ) -> file_hashing.ShardedFileHasher:
        return file_hashing.ShardedFileHasher(
            path, memory.SHA256(), start=start, end=end, shard_size=8
        )

    @pytest.mark.parametrize("model_fixture_name", test_support.all_test_models)
    def test_known_models(self, request, model_fixture_name):
        # Set up variables (arrange)
        testdata_path = request.path.parent / "testdata"
        test_path = testdata_path / "file_shard"
        test_class_path = test_path / "TestSerializer"
        golden_path = test_class_path / model_fixture_name
        should_update = request.config.getoption("update_goldens")
        model = request.getfixturevalue(model_fixture_name)

        # Compute model manifest (act)
        serializer = file_shard.Serializer(
            self._hasher_factory, allow_symlinks=True
        )
        manifest_file = serializer.serialize(model)
        items = _extract_shard_items_from_manifest(manifest_file)

        # Compare with golden, or write to golden (approximately "assert")
        if should_update:
            with open(golden_path, "w", encoding="utf-8") as f:
                for shard, digest in sorted(items.items()):
                    f.write(f"{shard}:{digest}\n")
        else:
            found_items: dict[manifest.Shard, str] = {}
            with open(golden_path, "r", encoding="utf-8") as f:
                for line in f:
                    shard, digest = _parse_shard_and_digest(line)
                    found_items[shard] = digest

            assert items == found_items

    @pytest.mark.parametrize("model_fixture_name", test_support.all_test_models)
    def test_known_models_small_shards(self, request, model_fixture_name):
        # Set up variables (arrange)
        testdata_path = request.path.parent / "testdata"
        test_path = testdata_path / "file_shard"
        test_class_path = test_path / "TestSerializer"
        golden_path = test_class_path / f"{model_fixture_name}_small_shards"
        should_update = request.config.getoption("update_goldens")
        model = request.getfixturevalue(model_fixture_name)

        # Compute model manifest (act)
        serializer = file_shard.Serializer(
            self._hasher_factory_small_shards, allow_symlinks=True
        )
        manifest_file = serializer.serialize(model)
        items = _extract_shard_items_from_manifest(manifest_file)

        # Compare with golden, or write to golden (approximately "assert")
        if should_update:
            with open(golden_path, "w", encoding="utf-8") as f:
                for shard, digest in sorted(items.items()):
                    f.write(f"{shard}:{digest}\n")
        else:
            found_items: dict[manifest.Shard, str] = {}
            with open(golden_path, "r", encoding="utf-8") as f:
                for line in f:
                    shard, digest = _parse_shard_and_digest(line)
                    found_items[shard] = digest

            assert items == found_items

    def test_file_manifest_unchanged_when_model_moved(self, sample_model_file):
        serializer = file_shard.Serializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_file)

        new_name = sample_model_file.with_name("new-file")
        new_file = sample_model_file.rename(new_name)
        new_manifest = serializer.serialize(new_file)

        assert manifest == new_manifest

    def test_file_manifest_changes_if_content_changes(self, sample_model_file):
        serializer = file_shard.Serializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_file)
        digests = set(test_support.extract_digests_from_manifest(manifest))

        sample_model_file.write_bytes(test_support.ANOTHER_MODEL_TEXT)
        new_manifest = serializer.serialize(sample_model_file)
        new_digests = set(
            test_support.extract_digests_from_manifest(new_manifest)
        )

        assert manifest != new_manifest
        assert len(digests) == len(new_digests)
        assert digests != new_digests

    def test_directory_model_with_only_known_file(self, sample_model_file):
        serializer = file_shard.Serializer(self._hasher_factory)
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
        serializer = file_shard.Serializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        new_name = sample_model_folder.with_name("new-root")
        new_model = sample_model_folder.rename(new_name)
        new_manifest = serializer.serialize(new_model)

        assert manifest == new_manifest

    def test_folder_model_empty_folder_not_included(self, sample_model_folder):
        serializer = file_shard.Serializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        altered_dir = test_support.get_first_directory(sample_model_folder)
        new_empty_dir = altered_dir / "empty"
        new_empty_dir.mkdir()
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest == new_manifest

    def test_folder_model_empty_file_not_included(self, sample_model_folder):
        serializer = file_shard.Serializer(self._hasher_factory)
        manifest = serializer.serialize(sample_model_folder)

        altered_dir = test_support.get_first_directory(sample_model_folder)
        new_empty_file = altered_dir / "empty"
        new_empty_file.write_text("")
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest == new_manifest

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
            shard = cast(manifest.Shard, key)
            if shard.path.name == new_name:
                old_shard = manifest.Shard(old_name, shard.start, shard.end)
                assert old_manifest._item_to_digest[old_shard] == digest
            else:
                assert old_manifest._item_to_digest[shard] == digest

    def test_folder_model_rename_file_only_changes_path_part(
        self, sample_model_folder
    ):
        serializer = file_shard.Serializer(self._hasher_factory)
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
            shard = cast(manifest.Shard, key)
            if new_name in shard.path.parts:
                parts = [
                    old_name if part == new_name else part
                    for part in shard.path.parts
                ]
                old = manifest.Shard(
                    pathlib.PurePosixPath(*parts), shard.start, shard.end
                )
                assert old_manifest._item_to_digest[old] == digest
            else:
                assert old_manifest._item_to_digest[shard] == digest

    def test_folder_model_rename_dir_only_changes_path_part(
        self, sample_model_folder
    ):
        serializer = file_shard.Serializer(self._hasher_factory)
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
        serializer = file_shard.Serializer(self._hasher_factory)
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
            shard = cast(manifest.Shard, key)
            if shard.path == expected_mismatch_path:
                # Note that the file size changes
                key = manifest.Shard(shard.path, 0, 23)
                assert old_manifest._item_to_digest[key] != digest
            else:
                assert old_manifest._item_to_digest[shard] == digest

    def test_folder_model_change_file(self, sample_model_folder):
        serializer = file_shard.Serializer(self._hasher_factory)
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
        serializer1 = file_shard.Serializer(self._hasher_factory)
        serializer2 = file_shard.Serializer(self._hasher_factory, max_workers=1)
        serializer3 = file_shard.Serializer(self._hasher_factory, max_workers=3)

        manifest1 = serializer1.serialize(sample_model_folder)
        manifest2 = serializer2.serialize(sample_model_folder)
        manifest3 = serializer3.serialize(sample_model_folder)

        assert manifest1 == manifest2
        assert manifest1 == manifest3

    def test_symlinks_disallowed_by_default(self, symlink_model_folder):
        serializer = file_shard.Serializer(self._hasher_factory)
        with pytest.raises(
            ValueError, match="Cannot use '.+' because it is a symlink."
        ):
            _ = serializer.serialize(symlink_model_folder)

    def test_shard_to_string(self):
        """Ensure the shard's `__str__` method behaves as assumed."""
        shard = manifest.Shard(pathlib.PurePosixPath("a"), 0, 42)
        assert str(shard) == "a:0:42"

    def test_ignore_list_respects_directories(self, sample_model_folder):
        serializer = file_shard.Serializer(self._hasher_factory)
        manifest1 = serializer.serialize(sample_model_folder)
        ignore_path = test_support.get_first_directory(sample_model_folder)
        manifest2 = serializer.serialize(
            sample_model_folder, ignore_paths=[ignore_path]
        )
        assert manifest1 != manifest2
        assert len(manifest1._item_to_digest) > len(manifest2._item_to_digest)
