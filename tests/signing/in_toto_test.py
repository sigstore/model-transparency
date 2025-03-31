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

"""Tests for in-toto signing payloads.

NOTE: This test uses a goldens setup to compare expected results with data from
files. If the golden tests are failing, regenerate the golden files with

  hatch test --update_goldens
"""

import pathlib

from google.protobuf import json_format
from in_toto_attestation.v1 import statement_pb2
import pytest

from model_signing._hashing import file
from model_signing._hashing import memory
from model_signing._serialization import serialize_by_file
from model_signing._serialization import serialize_by_file_shard
from model_signing.signing import in_toto
from tests import test_support


class TestDigestOfDigestsIntotoPayload:
    def _hasher_factory(self, path: pathlib.Path) -> file.FileHasher:
        return file.SimpleFileHasher(path, memory.SHA256())

    @pytest.mark.parametrize("model_fixture_name", test_support.all_test_models)
    def test_known_models(self, request, model_fixture_name):
        # Set up variables (arrange)
        testdata_path = request.path.parent / "testdata"
        test_path = testdata_path / "in_toto"
        test_class_path = test_path / "TestDigestOfDigestsIntotoPayload"
        golden_path = test_class_path / model_fixture_name
        should_update = request.config.getoption("update_goldens")
        model = request.getfixturevalue(model_fixture_name)

        # Compute payload (act)
        serializer = serialize_by_file.ManifestSerializer(
            self._hasher_factory, allow_symlinks=True
        )
        manifest = serializer.serialize(model)
        payload = in_toto.DigestOfDigestsIntotoPayload.from_manifest(manifest)

        # Compare with golden, or write to golden (approximately "assert")
        if should_update:
            with open(golden_path, "w", encoding="utf-8") as f:
                f.write(f"{json_format.MessageToJson(payload.statement.pb)}\n")
        else:
            with open(golden_path, "r", encoding="utf-8") as f:
                json_contents = f.read()
                expected_proto = json_format.Parse(
                    json_contents, statement_pb2.Statement()
                )

            assert payload.statement.pb == expected_proto

    def test_produces_valid_statements(self, sample_model_folder):
        serializer = serialize_by_file.ManifestSerializer(
            self._hasher_factory, allow_symlinks=True
        )
        manifest = serializer.serialize(sample_model_folder)

        payload = in_toto.DigestOfDigestsIntotoPayload.from_manifest(manifest)

        payload.statement.validate()


class TestDigestOfShardDigestsIntotoPayload:
    def _hasher_factory(
        self, path: pathlib.Path, start: int, end: int
    ) -> file.ShardedFileHasher:
        return file.ShardedFileHasher(
            path, memory.SHA256(), start=start, end=end
        )

    @pytest.mark.parametrize("model_fixture_name", test_support.all_test_models)
    def test_known_models(self, request, model_fixture_name):
        # Set up variables (arrange)
        testdata_path = request.path.parent / "testdata"
        test_path = testdata_path / "in_toto"
        test_class_path = test_path / "TestDigestOfShardDigestsIntotoPayload"
        golden_path = test_class_path / model_fixture_name
        should_update = request.config.getoption("update_goldens")
        model = request.getfixturevalue(model_fixture_name)

        # Compute payload (act)
        serializer = serialize_by_file_shard.ManifestSerializer(
            self._hasher_factory, allow_symlinks=True
        )
        manifest = serializer.serialize(model)
        payload = in_toto.DigestOfShardDigestsIntotoPayload.from_manifest(
            manifest
        )

        # Compare with golden, or write to golden (approximately "assert")
        if should_update:
            with open(golden_path, "w", encoding="utf-8") as f:
                f.write(f"{json_format.MessageToJson(payload.statement.pb)}\n")
        else:
            with open(golden_path, "r", encoding="utf-8") as f:
                json_contents = f.read()
                expected_proto = json_format.Parse(
                    json_contents, statement_pb2.Statement()
                )

            assert payload.statement.pb == expected_proto

    def test_produces_valid_statements(self, sample_model_folder):
        serializer = serialize_by_file_shard.ManifestSerializer(
            self._hasher_factory, allow_symlinks=True
        )
        manifest = serializer.serialize(sample_model_folder)

        payload = in_toto.DigestOfShardDigestsIntotoPayload.from_manifest(
            manifest
        )

        payload.statement.validate()


class TestDigestsIntotoPayload:
    def _hasher_factory(self, path: pathlib.Path) -> file.FileHasher:
        return file.SimpleFileHasher(path, memory.SHA256())

    @pytest.mark.parametrize("model_fixture_name", test_support.all_test_models)
    def test_known_models(self, request, model_fixture_name):
        # Set up variables (arrange)
        testdata_path = request.path.parent / "testdata"
        test_path = testdata_path / "in_toto"
        test_class_path = test_path / "TestDigestsIntotoPayload"
        golden_path = test_class_path / model_fixture_name
        should_update = request.config.getoption("update_goldens")
        model = request.getfixturevalue(model_fixture_name)

        # Compute payload (act)
        serializer = serialize_by_file.ManifestSerializer(
            self._hasher_factory, allow_symlinks=True
        )
        manifest = serializer.serialize(model)
        payload = in_toto.DigestsIntotoPayload.from_manifest(manifest)

        # Compare with golden, or write to golden (approximately "assert")
        if should_update:
            with open(golden_path, "w", encoding="utf-8") as f:
                f.write(f"{json_format.MessageToJson(payload.statement.pb)}\n")
        else:
            with open(golden_path, "r", encoding="utf-8") as f:
                json_contents = f.read()
                expected_proto = json_format.Parse(
                    json_contents, statement_pb2.Statement()
                )

            assert payload.statement.pb == expected_proto

    def test_produces_valid_statements(self, sample_model_folder):
        serializer = serialize_by_file.ManifestSerializer(
            self._hasher_factory, allow_symlinks=True
        )
        manifest = serializer.serialize(sample_model_folder)

        payload = in_toto.DigestsIntotoPayload.from_manifest(manifest)

        payload.statement.validate()


class TestShardDigestsIntotoPayload:
    def _hasher_factory(
        self, path: pathlib.Path, start: int, end: int
    ) -> file.ShardedFileHasher:
        return file.ShardedFileHasher(
            path, memory.SHA256(), start=start, end=end
        )

    @pytest.mark.parametrize("model_fixture_name", test_support.all_test_models)
    def test_known_models(self, request, model_fixture_name):
        # Set up variables (arrange)
        testdata_path = request.path.parent / "testdata"
        test_path = testdata_path / "in_toto"
        test_class_path = test_path / "TestShardDigestsIntotoPayload"
        golden_path = test_class_path / model_fixture_name
        should_update = request.config.getoption("update_goldens")
        model = request.getfixturevalue(model_fixture_name)

        # Compute payload (act)
        serializer = serialize_by_file_shard.ManifestSerializer(
            self._hasher_factory, allow_symlinks=True
        )
        manifest = serializer.serialize(model)
        payload = in_toto.ShardDigestsIntotoPayload.from_manifest(manifest)

        # Compare with golden, or write to golden (approximately "assert")
        if should_update:
            with open(golden_path, "w", encoding="utf-8") as f:
                f.write(f"{json_format.MessageToJson(payload.statement.pb)}\n")
        else:
            with open(golden_path, "r", encoding="utf-8") as f:
                json_contents = f.read()
                proto = json_format.Parse(
                    json_contents, statement_pb2.Statement()
                )

            assert payload.statement.pb == proto

    def test_produces_valid_statements(self, sample_model_folder):
        serializer = serialize_by_file_shard.ManifestSerializer(
            self._hasher_factory, allow_symlinks=True
        )
        manifest = serializer.serialize(sample_model_folder)

        payload = in_toto.ShardDigestsIntotoPayload.from_manifest(manifest)

        payload.statement.validate()
