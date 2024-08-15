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

"""Tests for binary signing payloads.

NOTE: This test uses a goldens setup to compare expected results with data from
files. If the golden tests are failing, regenerate the golden files with

  hatch test --update_goldens
"""

import pytest

from model_signing.hashing import file
from model_signing.hashing import memory
from model_signing.serialization import serialize_by_file
from model_signing.signing import as_bytes
from tests import test_support


class TestBytesPayload:
    @pytest.mark.parametrize("model_fixture_name", test_support.all_test_models)
    def test_known_models(self, request, model_fixture_name):
        # Set up variables (arrange)
        testdata_path = request.path.parent / "testdata"
        test_path = testdata_path / "as_bytes"
        test_class_path = test_path / "TestBytesPayload"
        golden_path = test_class_path / model_fixture_name
        should_update = request.config.getoption("update_goldens")
        model = request.getfixturevalue(model_fixture_name)

        # Compute payload (act)
        file_hasher = file.SimpleFileHasher(
            test_support.UNUSED_PATH, memory.SHA256()
        )
        serializer = serialize_by_file.DigestSerializer(
            file_hasher, memory.SHA256, allow_symlinks=True
        )
        manifest = serializer.serialize(model)
        payload = as_bytes.BytesPayload.from_manifest(manifest)

        # Compare with golden, or write to golden (approximately "assert")
        if should_update:
            with open(golden_path, "w", encoding="utf-8") as f:
                f.write(f"{payload.digest.hex()}\n")
        else:
            with open(golden_path, "r", encoding="utf-8") as f:
                expected_bytes = bytes.fromhex(f.read().strip())

            assert payload.digest == expected_bytes

    def test_only_runs_on_expected_manifest_types(self, sample_model_folder):
        serializer = serialize_by_file.ManifestSerializer(
            lambda f: file.SimpleFileHasher(f, memory.SHA256()),
            allow_symlinks=True,
        )
        manifest = serializer.serialize(sample_model_folder)

        with pytest.raises(TypeError, match="Only DigestManifest is supported"):
            as_bytes.BytesPayload.from_manifest(manifest)
