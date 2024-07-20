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

import dataclasses
import pathlib
import pytest

from model_signing.hashing import file
from model_signing.hashing import memory
from model_signing.manifest import manifest
from model_signing.serialization import serialize_by_file_shard
from model_signing.serialization import test_support


# NOTE: This test uses a golden setup to compute digest of several test
# models. If the golden tests are failing, regenerate the golden files with
#
#   pytest model_signing/serialization/ --update_goldens


class TestDigestSerializer:

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

    @pytest.mark.parametrize("model_fixture_name", test_support.all_test_models)
    def test_known_models(self, request, model_fixture_name):
        # Set up variables (arrange)
        testdata_path = request.path.parent / "testdata"
        test_path = testdata_path / "serialize_by_file_shard"
        test_class_path = test_path / "TestDigestSerializer"
        golden_path = test_class_path / model_fixture_name
        should_update = request.config.getoption("update_goldens")
        model = request.getfixturevalue(model_fixture_name)

        # Compute model manifest (act)
        serializer = serialize_by_file_shard.DigestSerializer(
            self._hasher_factory, memory.SHA256()
        )
        manifest = serializer.serialize(model)

        # Compare with golden, or write to golden (approximately "assert")
        if should_update:
            with open(golden_path, "w", encoding="utf-8") as f:
                f.write(f"{manifest.digest.digest_hex}\n")
        else:
            with open(golden_path, "r", encoding="utf-8") as f:
                expected_digest = f.read().strip()

            assert manifest.digest.digest_hex == expected_digest

    @pytest.mark.parametrize("model_fixture_name", test_support.all_test_models)
    def test_known_models_small_shards(self, request, model_fixture_name):
        # Set up variables (arrange)
        testdata_path = request.path.parent / "testdata"
        test_path = testdata_path / "serialize_by_file_shard"
        test_class_path = test_path / "TestDigestSerializer"
        golden_path = test_class_path / f"{model_fixture_name}_small_shards"
        should_update = request.config.getoption("update_goldens")
        model = request.getfixturevalue(model_fixture_name)

        # Compute model manifest (act)
        serializer = serialize_by_file_shard.DigestSerializer(
            self._hasher_factory_small_shards, memory.SHA256()
        )
        manifest = serializer.serialize(model)

        # Compare with golden, or write to golden (approximately "assert")
        if should_update:
            with open(golden_path, "w", encoding="utf-8") as f:
                f.write(f"{manifest.digest.digest_hex}\n")
        else:
            with open(golden_path, "r", encoding="utf-8") as f:
                expected_digest = f.read().strip()

            assert manifest.digest.digest_hex == expected_digest

    def test_file_hash_is_not_same_as_hash_of_content(self, sample_model_file):
        serializer = serialize_by_file_shard.DigestSerializer(
            self._hasher_factory, memory.SHA256()
        )

        manifest = serializer.serialize(sample_model_file)
        digest = memory.SHA256(test_support.KNOWN_MODEL_TEXT).compute()

        assert manifest.digest.digest_hex != digest.digest_hex

    def test_file_manifest_unchanged_when_model_moved(self, sample_model_file):
        serializer = serialize_by_file_shard.DigestSerializer(
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
        serializer = serialize_by_file_shard.DigestSerializer(
            self._hasher_factory, memory.SHA256()
        )
        manifest = serializer.serialize(sample_model_file)

        sample_model_file.write_bytes(test_support.ANOTHER_MODEL_TEXT)
        new_manifest = serializer.serialize(sample_model_file)

        assert manifest.digest.algorithm == new_manifest.digest.algorithm
        assert manifest.digest.digest_value != new_manifest.digest.digest_value

    def test_directory_model_with_only_known_file(self, sample_model_file):
        serializer = serialize_by_file_shard.DigestSerializer(
            self._hasher_factory, memory.SHA256()
        )
        manifest_file = serializer.serialize(sample_model_file)
        content_digest = memory.SHA256(test_support.KNOWN_MODEL_TEXT).compute()

        manifest = serializer.serialize(sample_model_file.parent)

        assert manifest_file != manifest
        assert manifest.digest.digest_hex != content_digest.digest_hex

    def test_folder_model_hash_is_same_if_model_is_moved(
        self, sample_model_folder
    ):
        serializer = serialize_by_file_shard.DigestSerializer(
            self._hasher_factory, memory.SHA256()
        )
        manifest = serializer.serialize(sample_model_folder)

        new_name = sample_model_folder.with_name("new-root")
        new_model = sample_model_folder.rename(new_name)
        new_manifest = serializer.serialize(new_model)

        assert manifest == new_manifest

    def test_folder_model_empty_folder_not_included(self, sample_model_folder):
        serializer = serialize_by_file_shard.DigestSerializer(
            self._hasher_factory, memory.SHA256()
        )
        manifest = serializer.serialize(sample_model_folder)

        altered_dir = test_support.get_first_directory(sample_model_folder)
        new_empty_dir = altered_dir / "empty"
        new_empty_dir.mkdir()
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest == new_manifest

    def test_folder_model_empty_file_not_included(self, sample_model_folder):
        serializer = serialize_by_file_shard.DigestSerializer(
            self._hasher_factory, memory.SHA256()
        )
        manifest = serializer.serialize(sample_model_folder)

        altered_dir = test_support.get_first_directory(sample_model_folder)
        new_empty_file = altered_dir / "empty"
        new_empty_file.write_text("")
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest == new_manifest

    def test_folder_model_rename_file(self, sample_model_folder):
        serializer = serialize_by_file_shard.DigestSerializer(
            self._hasher_factory, memory.SHA256()
        )
        manifest = serializer.serialize(sample_model_folder)

        altered_dir = test_support.get_first_directory(sample_model_folder)
        file_to_rename = test_support.get_first_file(altered_dir)
        new_name = file_to_rename.with_name("new-file")
        file_to_rename.rename(new_name)
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest != new_manifest

    def test_folder_model_rename_dir(self, sample_model_folder):
        serializer = serialize_by_file_shard.DigestSerializer(
            self._hasher_factory, memory.SHA256()
        )
        manifest = serializer.serialize(sample_model_folder)

        dir_to_rename = test_support.get_first_directory(sample_model_folder)
        new_name = dir_to_rename.with_name("new-dir")
        dir_to_rename.rename(new_name)
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest != new_manifest

    def test_folder_model_replace_file_empty_folder(self, sample_model_folder):
        serializer = serialize_by_file_shard.DigestSerializer(
            self._hasher_factory, memory.SHA256()
        )
        manifest = serializer.serialize(sample_model_folder)

        altered_dir = test_support.get_first_directory(sample_model_folder)
        file_to_replace = test_support.get_first_file(altered_dir)
        file_to_replace.unlink()
        file_to_replace.mkdir()
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest != new_manifest

    def test_folder_model_change_file(self, sample_model_folder):
        serializer = serialize_by_file_shard.DigestSerializer(
            self._hasher_factory, memory.SHA256()
        )
        manifest = serializer.serialize(sample_model_folder)

        altered_dir = test_support.get_first_directory(sample_model_folder)
        file_to_change = test_support.get_first_file(altered_dir)
        file_to_change.write_bytes(test_support.KNOWN_MODEL_TEXT)
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest != new_manifest

    def test_empty_folder_hashes_same_as_empty_file(
        self, empty_model_file, empty_model_folder
    ):
        serializer = serialize_by_file_shard.DigestSerializer(
            self._hasher_factory, memory.SHA256()
        )

        folder_manifest = serializer.serialize(empty_model_folder)
        file_manifest = serializer.serialize(empty_model_file)

        assert folder_manifest == file_manifest

    def test_model_with_empty_folder_hashes_same_as_with_empty_file(
        self, sample_model_folder
    ):
        serializer = serialize_by_file_shard.DigestSerializer(
            self._hasher_factory, memory.SHA256()
        )

        # Compute digest of model with empty folder
        altered_dir = test_support.get_first_directory(sample_model_folder)
        new_empty_dir = altered_dir / "empty"
        new_empty_dir.mkdir()
        folder_manifest = serializer.serialize(sample_model_folder)

        # Compute digest of model with empty file
        new_empty_dir.rmdir()
        new_empty_file = altered_dir / "empty"
        new_empty_file.write_text("")
        file_manifest = serializer.serialize(sample_model_folder)

        assert folder_manifest == file_manifest

    def test_max_workers_does_not_change_digest(self, sample_model_folder):
        serializer1 = serialize_by_file_shard.DigestSerializer(
            self._hasher_factory, memory.SHA256()
        )
        manifest1 = serializer1.serialize(sample_model_folder)

        serializer2 = serialize_by_file_shard.DigestSerializer(
            self._hasher_factory, memory.SHA256(), max_workers=2
        )
        manifest2 = serializer2.serialize(sample_model_folder)

        assert manifest1 == manifest2

    def test_shard_size_changes_digests(self, sample_model_folder):
        serializer1 = serialize_by_file_shard.DigestSerializer(
            self._hasher_factory, memory.SHA256()
        )
        manifest1 = serializer1.serialize(sample_model_folder)

        serializer2 = serialize_by_file_shard.DigestSerializer(
            self._hasher_factory_small_shards, memory.SHA256()
        )
        manifest2 = serializer2.serialize(sample_model_folder)

        assert manifest1.digest.digest_value != manifest2.digest.digest_value


@dataclasses.dataclass(frozen=True, order=True)
class _Shard:
    """A shard of a file from a manifest."""

    path: str
    start: int
    end: int


def _extract_shard_items_from_manifest(
    manifest: manifest.ShardLevelManifest,
) -> dict[_Shard, str]:
    """Builds a dictionary representation of the items in a manifest.

    Every item is mapped to its digest.

    Used in multiple tests to check that we obtained the expected manifest.
    """
    return {
        # convert to file path (relative to model) string and endpoints
        _Shard(str(shard[0]), shard[1], shard[2]): digest.digest_hex
        for shard, digest in manifest._item_to_digest.items()
    }


def _parse_shard_and_digest(line: str) -> tuple[_Shard, str]:
    """Reads a file shard and its digest from a line in the golden file.

    Args:
        line: The line to parse.

    Returns:
        The shard tuple and the digest corresponding to the line that was read.
    """
    path, start, end, digest = line.strip().split(":")
    shard = _Shard(path, int(start), int(end))
    return shard, digest


class TestManifestSerializer:

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

    @pytest.mark.parametrize("model_fixture_name", test_support.all_test_models)
    def test_known_models(self, request, model_fixture_name):
        # Set up variables (arrange)
        testdata_path = request.path.parent / "testdata"
        test_path = testdata_path / "serialize_by_file_shard"
        test_class_path = test_path / "TestManifestSerializer"
        golden_path = test_class_path / model_fixture_name
        should_update = request.config.getoption("update_goldens")
        model = request.getfixturevalue(model_fixture_name)

        # Compute model manifest (act)
        serializer = serialize_by_file_shard.ManifestSerializer(
            self._hasher_factory
        )
        manifest = serializer.serialize(model)
        items = _extract_shard_items_from_manifest(manifest)

        # Compare with golden, or write to golden (approximately "assert")
        if should_update:
            with open(golden_path, "w", encoding="utf-8") as f:
                for shard, digest in sorted(items.items()):
                    f.write(
                        f"{shard.path}:{shard.start}:{shard.end}:{digest}\n"
                    )
        else:
            found_items: dict[_Shard, str] = {}
            with open(golden_path, "r", encoding="utf-8") as f:
                for line in f:
                    shard, digest = _parse_shard_and_digest(line)
                    found_items[shard] = digest

            assert items == found_items

    @pytest.mark.parametrize("model_fixture_name", test_support.all_test_models)
    def test_known_models_small_shards(self, request, model_fixture_name):
        # Set up variables (arrange)
        testdata_path = request.path.parent / "testdata"
        test_path = testdata_path / "serialize_by_file_shard"
        test_class_path = test_path / "TestManifestSerializer"
        golden_path = test_class_path / f"{model_fixture_name}_small_shards"
        should_update = request.config.getoption("update_goldens")
        model = request.getfixturevalue(model_fixture_name)

        # Compute model manifest (act)
        serializer = serialize_by_file_shard.ManifestSerializer(
            self._hasher_factory_small_shards
        )
        manifest = serializer.serialize(model)
        items = _extract_shard_items_from_manifest(manifest)

        # Compare with golden, or write to golden (approximately "assert")
        if should_update:
            with open(golden_path, "w", encoding="utf-8") as f:
                for shard, digest in sorted(items.items()):
                    f.write(
                        f"{shard.path}:{shard.start}:{shard.end}:{digest}\n"
                    )
        else:
            found_items: dict[_Shard, str] = {}
            with open(golden_path, "r", encoding="utf-8") as f:
                for line in f:
                    shard, digest = _parse_shard_and_digest(line)
                    found_items[shard] = digest

            assert items == found_items

    def test_file_manifest_unchanged_when_model_moved(self, sample_model_file):
        serializer = serialize_by_file_shard.ManifestSerializer(
            self._hasher_factory
        )
        manifest = serializer.serialize(sample_model_file)

        new_name = sample_model_file.with_name("new-file")
        new_file = sample_model_file.rename(new_name)
        new_manifest = serializer.serialize(new_file)

        assert manifest == new_manifest

    def test_file_manifest_changes_if_content_changes(self, sample_model_file):
        serializer = serialize_by_file_shard.ManifestSerializer(
            self._hasher_factory
        )
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
        serializer = serialize_by_file_shard.ManifestSerializer(
            self._hasher_factory
        )
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
        serializer = serialize_by_file_shard.ManifestSerializer(
            self._hasher_factory
        )
        manifest = serializer.serialize(sample_model_folder)

        new_name = sample_model_folder.with_name("new-root")
        new_model = sample_model_folder.rename(new_name)
        new_manifest = serializer.serialize(new_model)

        assert manifest == new_manifest

    def test_folder_model_empty_folder_not_included(self, sample_model_folder):
        serializer = serialize_by_file_shard.ManifestSerializer(
            self._hasher_factory
        )
        manifest = serializer.serialize(sample_model_folder)

        altered_dir = test_support.get_first_directory(sample_model_folder)
        new_empty_dir = altered_dir / "empty"
        new_empty_dir.mkdir()
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest == new_manifest

    def test_folder_model_empty_file_not_included(self, sample_model_folder):
        serializer = serialize_by_file_shard.ManifestSerializer(
            self._hasher_factory
        )
        manifest = serializer.serialize(sample_model_folder)

        altered_dir = test_support.get_first_directory(sample_model_folder)
        new_empty_file = altered_dir / "empty"
        new_empty_file.write_text("")
        new_manifest = serializer.serialize(sample_model_folder)

        assert manifest == new_manifest

    def _check_manifests_match_except_on_renamed_file(
        self,
        old_manifest: manifest.ShardLevelManifest,
        new_manifest: manifest.ShardLevelManifest,
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
        for shard, digest in new_manifest._item_to_digest.items():
            path, start, end = shard
            if path.name == new_name:
                old_shard = (old_name, start, end)
                assert old_manifest._item_to_digest[old_shard] == digest
            else:
                assert old_manifest._item_to_digest[shard] == digest

    def test_folder_model_rename_file_only_changes_path_part(
        self, sample_model_folder
    ):
        serializer = serialize_by_file_shard.ManifestSerializer(
            self._hasher_factory
        )
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
        old_manifest: manifest.ShardLevelManifest,
        new_manifest: manifest.ShardLevelManifest,
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
        for shard, digest in new_manifest._item_to_digest.items():
            path, start, end = shard
            if new_name in path.parts:
                parts = [
                    old_name if part == new_name else part
                    for part in path.parts
                ]
                old = (pathlib.PurePosixPath(*parts), start, end)
                assert old_manifest._item_to_digest[old] == digest
            else:
                assert old_manifest._item_to_digest[shard] == digest

    def test_folder_model_rename_dir_only_changes_path_part(
        self, sample_model_folder
    ):
        serializer = serialize_by_file_shard.ManifestSerializer(
            self._hasher_factory
        )
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
        serializer = serialize_by_file_shard.ManifestSerializer(
            self._hasher_factory
        )
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
        old_manifest: manifest.ShardLevelManifest,
        new_manifest: manifest.ShardLevelManifest,
        expected_mismatch_path: pathlib.PurePath,
    ):
        """Checks that the manifests match, except for given path."""
        assert old_manifest != new_manifest
        assert len(new_manifest._item_to_digest) == len(
            old_manifest._item_to_digest
        )
        for shard, digest in new_manifest._item_to_digest.items():
            path, _, _ = shard
            if path == expected_mismatch_path:
                # Note that the file size changes
                assert old_manifest._item_to_digest[(path, 0, 23)] != digest
            else:
                assert old_manifest._item_to_digest[shard] == digest

    def test_folder_model_change_file(self, sample_model_folder):
        serializer = serialize_by_file_shard.ManifestSerializer(
            self._hasher_factory
        )
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
        serializer1 = serialize_by_file_shard.ManifestSerializer(
            self._hasher_factory
        )
        serializer2 = serialize_by_file_shard.ManifestSerializer(
            self._hasher_factory, max_workers=1
        )
        serializer3 = serialize_by_file_shard.ManifestSerializer(
            self._hasher_factory, max_workers=3
        )

        manifest1 = serializer1.serialize(sample_model_folder)
        manifest2 = serializer2.serialize(sample_model_folder)
        manifest3 = serializer3.serialize(sample_model_folder)

        assert manifest1 == manifest2
        assert manifest1 == manifest3
