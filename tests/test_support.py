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

"""Helpers and constants used in fixtures and tests. Not in the public API."""

import itertools
import pathlib

from model_signing.manifest import manifest


# Model contents
KNOWN_MODEL_TEXT: bytes = b"This is a simple model"
ANOTHER_MODEL_TEXT: bytes = b"This is another simple model"


# Constant for unused path when we need to pass a path as argument to internal
# API but we don't use it.
UNUSED_PATH = pathlib.Path("unused")


# All models to use in testing. Each of these is defined as a fixture in
# conftest.py. Here, we used them as strings, these names must match the
# function name used for the fixture.
all_test_models = [
    "sample_model_file",
    "sample_model_folder",
    "deep_model_folder",
    "empty_model_file",
    "empty_model_folder",
    "model_folder_with_empty_file",
    "symlink_model_folder",
]


# All directory models to use in testing, where only non empty directory models
# are supported. See also `all_test_models` comments.
all_non_empty_directory_test_models = [
    "sample_model_folder",
    "deep_model_folder",
    "model_folder_with_empty_file",
    "symlink_model_folder",
]


# All files models to use in testing, where only file models are supported.
all_file_test_models = [
    "sample_model_file",
    "empty_model_file",
    "model_folder_with_empty_file",
]


def get_first_directory(path: pathlib.Path) -> pathlib.Path:
    """Returns the first directory that is a children of path.

    It is assumed that there is always such a path.
    """
    return [d for d in path.iterdir() if d.is_dir()][0]


def get_first_file(path: pathlib.Path) -> pathlib.Path:
    """Returns the first file that is a children of path.

    It is assumed that there is always such a path.
    """
    return [f for f in path.iterdir() if f.is_file()][0]


def extract_digests_from_manifest(
    manifest: manifest.FileLevelManifest,
) -> list[str]:
    """Extracts the hex digest for every subject in a manifest.

    Used in multiple tests to check that we obtained the expected digests.
    """
    return [d.digest_hex for d in manifest._item_to_digest.values()]


def extract_items_from_manifest(
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


def count_files(path: pathlib.Path) -> int:
    """Counts the number of files that are children of path.

    If path is a file, the count returned is 1.
    """
    count = 0
    for child_path in itertools.chain((path,), path.glob("**/*")):
        if child_path.is_file():
            count += 1
    return count
