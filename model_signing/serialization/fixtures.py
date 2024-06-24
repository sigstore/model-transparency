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

"""Test fixtures to share between tests. Not part of the public API."""

import pytest

from model_signing.serialization import fixtures_constants


# Note: Don't make fixtures with global scope as we are altering the models!
@pytest.fixture
def sample_model_file(tmp_path_factory):
    file = tmp_path_factory.mktemp("model") / "file"
    file.write_bytes(fixtures_constants.KNOWN_MODEL_TEXT)
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
