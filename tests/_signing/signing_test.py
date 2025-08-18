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

from model_signing._hashing import io
from model_signing._hashing import memory
from model_signing._serialization import file
from model_signing._serialization import file_shard
from model_signing.signing import signing
from tests import test_support


class TestPayload:
    def _file_hasher_factory(self, path: pathlib.Path) -> io.FileHasher:
        return io.SimpleFileHasher(path, memory.SHA256())

    def _shard_hasher_factory(
        self, path: pathlib.Path, start: int, end: int
    ) -> io.ShardedFileHasher:
        return io.ShardedFileHasher(path, memory.SHA256(), start=start, end=end)

    def _small_shard_hasher_factory(
        self, path: pathlib.Path, start: int, end: int
    ) -> io.ShardedFileHasher:
        return io.ShardedFileHasher(
            path, memory.SHA256(), start=start, end=end, shard_size=8
        )

    def _run_test(
        self, testdata_path, golden_name, should_update, model, serializer
    ):
        # Set up variables (arrange)
        test_path = testdata_path / "signing"
        test_class_path = test_path / "TestPayload"
        golden_path = test_class_path / golden_name

        # Compute payload (act)
        manifest = serializer.serialize(model)
        payload = signing.Payload(manifest)

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

    @pytest.mark.parametrize("model_fixture_name", test_support.all_test_models)
    def test_known_models_file(self, request, model_fixture_name):
        self._run_test(
            request.path.parent / "testdata",
            model_fixture_name,
            request.config.getoption("update_goldens"),
            request.getfixturevalue(model_fixture_name),
            file.Serializer(self._file_hasher_factory, allow_symlinks=True),
        )

    @pytest.mark.parametrize("model_fixture_name", test_support.all_test_models)
    def test_known_models_shard(self, request, model_fixture_name):
        self._run_test(
            request.path.parent / "testdata",
            f"{model_fixture_name}_shard",
            request.config.getoption("update_goldens"),
            request.getfixturevalue(model_fixture_name),
            file_shard.Serializer(
                self._shard_hasher_factory, allow_symlinks=True
            ),
        )

    @pytest.mark.parametrize("model_fixture_name", test_support.all_test_models)
    def test_known_models_small_shards(self, request, model_fixture_name):
        self._run_test(
            request.path.parent / "testdata",
            f"{model_fixture_name}_small_shards",
            request.config.getoption("update_goldens"),
            request.getfixturevalue(model_fixture_name),
            file_shard.Serializer(
                self._small_shard_hasher_factory, allow_symlinks=True
            ),
        )

    @pytest.mark.parametrize("model_fixture_name", test_support.all_test_models)
    def test_restore_manifest_file(self, request, model_fixture_name):
        model = request.getfixturevalue(model_fixture_name)
        serializer = file.Serializer(
            self._file_hasher_factory, allow_symlinks=True
        )
        manifest = serializer.serialize(model)

        payload = signing.Payload(manifest)
        statement_dict = json_format.MessageToDict(payload.statement.pb)

        restored = signing.dsse_payload_to_manifest(statement_dict)

        assert restored == manifest
        assert restored.model_name == manifest.model_name
        assert restored.serialization_type == manifest.serialization_type

    @pytest.mark.parametrize("model_fixture_name", test_support.all_test_models)
    def test_restore_manifest_shard(self, request, model_fixture_name):
        model = request.getfixturevalue(model_fixture_name)
        serializer = file_shard.Serializer(
            self._shard_hasher_factory, allow_symlinks=True
        )
        manifest = serializer.serialize(model)

        payload = signing.Payload(manifest)
        statement_dict = json_format.MessageToDict(payload.statement.pb)

        restored = signing.dsse_payload_to_manifest(statement_dict)

        assert restored == manifest
        assert restored.model_name == manifest.model_name
        assert restored.serialization_type == manifest.serialization_type

    def test_produces_valid_statements(self, sample_model_folder):
        serializer = file.Serializer(
            self._file_hasher_factory, allow_symlinks=True
        )
        manifest = serializer.serialize(sample_model_folder)

        payload = signing.Payload(manifest)

        payload.statement.validate()
