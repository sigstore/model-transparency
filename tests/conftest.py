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

import os
import pathlib

import pytest

from tests import test_support


def pytest_addoption(parser):
    """Adds a flag argument to update the goldens."""
    parser.addoption(
        "--update_goldens",
        action="store_true",
        default=False,
        help="update golden files",
    )


# Note: Don't make fixtures with global scope as we are altering the models!
@pytest.fixture
def sample_model_file(tmp_path_factory):
    """A model with just a single file."""
    file = tmp_path_factory.mktemp("model") / "file"
    file.write_bytes(test_support.KNOWN_MODEL_TEXT)
    return file


@pytest.fixture
def empty_model_file(tmp_path_factory):
    """A model with just an empty file."""
    file = tmp_path_factory.mktemp("model") / "file"
    file.write_bytes(b"")
    return file


@pytest.fixture
def sample_model_folder(tmp_path_factory):
    """A model with multiple files and directories."""
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
    """A model with just an empty directory."""
    model_root = tmp_path_factory.mktemp("model") / "root"
    model_root.mkdir()
    return model_root


@pytest.fixture
def model_folder_with_empty_file(tmp_path_factory):
    """A model with just an empty file, inside a directory."""
    model_root = tmp_path_factory.mktemp("model") / "root"
    model_root.mkdir()

    empty_file = model_root / "empty_file"
    empty_file.write_bytes(b"")

    return model_root


@pytest.fixture
def deep_model_folder(tmp_path_factory):
    """A model with a deep directory hierarchy."""
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


@pytest.fixture
def symlink_model_folder(
    tmp_path_factory: pytest.TempPathFactory,
) -> pathlib.Path:
    """A model folder with a symlink to an external file."""
    external_file = tmp_path_factory.mktemp("external") / "file"
    external_file.write_bytes(test_support.KNOWN_MODEL_TEXT)
    model_dir = tmp_path_factory.mktemp("model")
    symlink_file = model_dir / "symlink_file"
    os.symlink(external_file.absolute(), symlink_file.absolute())
    return model_dir
