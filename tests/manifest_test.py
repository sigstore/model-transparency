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

from model_signing import manifest
from model_signing._hashing import hashing


class TestFileLevelManifest:
    _manifest_type = manifest._FileSerialization("test_only_serialization")

    def test_insert_order_does_not_matter(self):
        path1 = pathlib.PurePath("file1")
        digest1 = hashing.Digest("test", b"abcd")
        item1 = manifest.FileManifestItem(path=path1, digest=digest1)

        path2 = pathlib.PurePath("file2")
        digest2 = hashing.Digest("test", b"efgh")
        item2 = manifest.FileManifestItem(path=path2, digest=digest2)

        manifest1 = manifest.Manifest(
            "test_model", [item1, item2], self._manifest_type
        )
        manifest2 = manifest.Manifest(
            "test_model", [item2, item1], self._manifest_type
        )

        assert manifest1 == manifest2

    @pytest.mark.parametrize("num_items", [1, 3, 5])
    def test_manifest_has_all_resource_descriptors(self, num_items):
        items: list[manifest.FileManifestItem] = []
        for i in range(num_items):
            path = pathlib.PurePath(f"file{i}")
            digest = hashing.Digest("test", b"hash{i}")
            item = manifest.FileManifestItem(path=path, digest=digest)
            items.append(item)
        manifest_file = manifest.Manifest(
            "test_model", items, self._manifest_type
        )

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
        manifest_file = manifest.Manifest(
            "test_model", [item2, item1], self._manifest_type
        )
        descriptors = list(manifest_file.resource_descriptors())

        # But we expect the descriptors to be in order by file
        assert descriptors[0].identifier == "file1"
        assert descriptors[1].identifier == "file2"
        assert descriptors[0].digest.digest_value == b"hash1"
        assert descriptors[1].digest.digest_value == b"hash2"


class TestShard:
    def test_round_trip_from_shard(self):
        shard = manifest._Shard(pathlib.PurePosixPath("file"), 0, 42)
        shard_str = str(shard)
        assert manifest._Shard.from_str(shard_str) == shard

    def test_round_trip_from_string(self):
        shard_str = "file:0:42"
        shard = manifest._Shard.from_str(shard_str)
        assert str(shard) == shard_str

    def test_invalid_shard_str_too_few_components(self):
        shard_str = "file"

        with pytest.raises(ValueError, match="Expected 3 components"):
            manifest._Shard.from_str(shard_str)

    def test_invalid_shard_str_too_many_components(self):
        shard_str = "file:0:1:2"

        with pytest.raises(ValueError, match="Expected 3 components"):
            manifest._Shard.from_str(shard_str)

    def test_invalid_shard_bad_type_for_start_offset(self):
        shard_str = "file:zero:4"

        with pytest.raises(ValueError, match="invalid literal for int"):
            manifest._Shard.from_str(shard_str)

    def test_invalid_shard_bad_type_for_endart_offset(self):
        shard_str = "file:0:four"

        with pytest.raises(ValueError, match="invalid literal for int"):
            manifest._Shard.from_str(shard_str)


class TestShardLevelManifest:
    _manifest_type = manifest._ShardSerialization("test_only_serialization", 42)

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

        manifest1 = manifest.Manifest(
            "test_model", [item1, item2], self._manifest_type
        )
        manifest2 = manifest.Manifest(
            "test_model", [item2, item1], self._manifest_type
        )

        assert manifest1 == manifest2

    def test_same_path_different_shards_gives_different_manifest(self):
        path = pathlib.PurePath("file")
        digest = hashing.Digest("test_model", b"abcd")

        item = manifest.ShardedFileManifestItem(
            path=path, digest=digest, start=0, end=2
        )
        manifest1 = manifest.Manifest("test_model", [item], self._manifest_type)

        item = manifest.ShardedFileManifestItem(
            path=path, digest=digest, start=2, end=4
        )
        manifest2 = manifest.Manifest("test_model", [item], self._manifest_type)

        assert manifest1 != manifest2

    @pytest.mark.parametrize("num_items", [1, 3, 5])
    def test_manifest_has_all_resource_descriptors(self, num_items):
        items: list[manifest.ShardedFileManifestItem] = []
        for i in range(num_items):
            path = pathlib.PurePath("file")
            digest = hashing.Digest("test_model", b"hash{i}")
            item = manifest.ShardedFileManifestItem(
                path=path, digest=digest, start=i, end=i + 2
            )
            items.append(item)
        manifest_file = manifest.Manifest(
            "test_model", items, self._manifest_type
        )

        descriptors = list(manifest_file.resource_descriptors())

        assert len(descriptors) == num_items

    def test_manifest_has_the_correct_resource_descriptors(self):
        path_to_file1 = pathlib.PurePath("file1")
        digest1 = hashing.Digest("test_model", b"hash1")
        item1 = manifest.ShardedFileManifestItem(
            path=path_to_file1, digest=digest1, start=0, end=4
        )

        # First file, but second shard
        digest2 = hashing.Digest("test_model", b"hash2")
        item2 = manifest.ShardedFileManifestItem(
            path=path_to_file1, digest=digest2, start=4, end=8
        )

        path_to_file2 = pathlib.PurePath("file2")
        digest3 = hashing.Digest("test_model", b"hash3")
        item3 = manifest.ShardedFileManifestItem(
            path=path_to_file2, digest=digest3, start=0, end=4
        )

        # Note order is not preserved (random permutation)
        manifest_file = manifest.Manifest(
            "test_model", [item2, item3, item1], self._manifest_type
        )
        descriptors = list(manifest_file.resource_descriptors())

        # But we expect the descriptors to be in order by file shard
        assert descriptors[0].identifier == "file1:0:4"
        assert descriptors[1].identifier == "file1:4:8"
        assert descriptors[2].identifier == "file2:0:4"
        assert descriptors[0].digest.digest_value == b"hash1"
        assert descriptors[1].digest.digest_value == b"hash2"
        assert descriptors[2].digest.digest_value == b"hash3"


class TestManifestFromSignature:
    def test_from_signature_rejects_inconsistent_manifest(self, tmp_path):
        import base64
        import json

        # Create a Sigstore bundle with inconsistent root digest
        # The subject digest doesn't match the hash of the resources
        payload_dict = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": "test_model",
                    "digest": {
                        "sha256": (
                            "0b8a5a8c8e8f1a8b8c8d8e8f2a8b8c8d8e8f3a8b8c8d"
                            "8e8f4a8b8c8d8e8f5a8b"
                        )
                    },
                }
            ],
            "predicateType": "https://model_signing/signature/v1.0",
            "predicate": {
                "serialization": {
                    "method": "files",
                    "hash_type": "sha256",
                    "allow_symlinks": False,
                    "ignore_paths": [],
                },
                "resources": [
                    {
                        "name": "file1.txt",
                        "algorithm": "sha256",
                        "digest": (
                            "abcd1234abcd1234abcd1234abcd1234"
                            "abcd1234abcd1234abcd1234abcd1234"
                        ),
                    },
                    {
                        "name": "file2.txt",
                        "algorithm": "sha256",
                        "digest": (
                            "5678dcba5678dcba5678dcba5678dcba"
                            "5678dcba5678dcba5678dcba5678dcba"
                        ),
                    },
                ],
            },
        }

        # Create DSSE envelope
        payload_json = json.dumps(payload_dict)
        payload_b64 = base64.b64encode(payload_json.encode("utf-8")).decode(
            "utf-8"
        )

        bundle_dict = {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "publicKey": {"hint": "test"},
                "tlogEntries": [],
            },
            "dsseEnvelope": {
                "payload": payload_b64,
                "payloadType": "application/vnd.in-toto+json",
                "signatures": [{"sig": "fake_signature"}],
            },
        }

        # Write to file
        sig_file = tmp_path / "test.sig"
        sig_file.write_text(json.dumps(bundle_dict), encoding="utf-8")

        # Verify that inconsistent manifest is rejected
        with pytest.raises(ValueError, match="Manifest is inconsistent"):
            manifest.Manifest.from_signature(sig_file)

    def test_from_signature_extracts_valid_manifest(self, tmp_path):
        import base64
        import hashlib
        import json

        # Create valid SHA256 hex digests (64 chars each)
        digest1_hex = (
            "abcd1234abcd1234abcd1234abcd1234"
            "abcd1234abcd1234abcd1234abcd1234"
        )
        digest2_hex = (
            "5678dcba5678dcba5678dcba5678dcba"
            "5678dcba5678dcba5678dcba5678dcba"
        )

        digest1_bytes = bytes.fromhex(digest1_hex)
        digest2_bytes = bytes.fromhex(digest2_hex)

        # Compute root digest (SHA256 of both digests concatenated)
        hasher = hashlib.sha256()
        hasher.update(digest1_bytes)
        hasher.update(digest2_bytes)
        root_digest = hasher.hexdigest()

        payload_dict = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {"name": "test_model", "digest": {"sha256": root_digest}}
            ],
            "predicateType": "https://model_signing/signature/v1.0",
            "predicate": {
                "serialization": {
                    "method": "files",
                    "hash_type": "sha256",
                    "allow_symlinks": False,
                    "ignore_paths": [],
                },
                "resources": [
                    {
                        "name": "file1.txt",
                        "algorithm": "sha256",
                        "digest": digest1_hex,
                    },
                    {
                        "name": "file2.txt",
                        "algorithm": "sha256",
                        "digest": digest2_hex,
                    },
                ],
            },
        }

        payload_json = json.dumps(payload_dict)
        payload_b64 = base64.b64encode(payload_json.encode("utf-8")).decode(
            "utf-8"
        )

        bundle_dict = {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "publicKey": {"hint": "test"},
                "tlogEntries": [],
            },
            "dsseEnvelope": {
                "payload": payload_b64,
                "payloadType": "application/vnd.in-toto+json",
                "signatures": [{"sig": "fake_signature"}],
            },
        }

        sig_file = tmp_path / "test.sig"
        sig_file.write_text(json.dumps(bundle_dict), encoding="utf-8")

        # Extract manifest
        extracted_manifest = manifest.Manifest.from_signature(sig_file)

        # Verify the manifest has the correct files
        descriptors = list(extracted_manifest.resource_descriptors())
        assert len(descriptors) == 2
        assert descriptors[0].identifier == "file1.txt"
        assert descriptors[1].identifier == "file2.txt"
        assert descriptors[0].digest.digest_hex == digest1_hex
        assert descriptors[1].digest.digest_hex == digest2_hex
        assert extracted_manifest.model_name == "test_model"

    def test_from_signature_file_not_found(self, tmp_path):
        non_existent = tmp_path / "does_not_exist.sig"
        with pytest.raises(FileNotFoundError):
            manifest.Manifest.from_signature(non_existent)

    def test_from_signature_invalid_json(self, tmp_path):
        import json

        sig_file = tmp_path / "invalid.sig"
        sig_file.write_text("not valid json", encoding="utf-8")
        with pytest.raises(json.JSONDecodeError):
            manifest.Manifest.from_signature(sig_file)

    def test_from_signature_missing_envelope(self, tmp_path):
        sig_file = tmp_path / "missing_envelope.sig"
        sig_file.write_text("{}", encoding="utf-8")
        with pytest.raises(
            ValueError, match="does not contain a DSSE envelope"
        ):
            manifest.Manifest.from_signature(sig_file)
