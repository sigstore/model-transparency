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

from model_signing._hashing import file_hashing
from model_signing._hashing import memory


# some constants used throughout testing
_HEADER: str = "Some "
_CONTENT: str = "text."  # note that these have the same length
_FULL_CONTENT = _HEADER + _CONTENT
_SHARD_SIZE = len(_HEADER)
_UNUSED_PATH = pathlib.Path("unused")


@pytest.fixture(scope="class")
def sample_file(tmp_path_factory):
    file_path = tmp_path_factory.mktemp("dir") / "text.txt"
    file_path.write_text(_FULL_CONTENT)
    return file_path


@pytest.fixture(scope="class")
def sample_file_content_only(tmp_path_factory):
    file_path = tmp_path_factory.mktemp("dir") / "text.txt"
    file_path.write_text(_CONTENT)
    return file_path


@pytest.fixture(scope="class")
def expected_digest():
    # To ensure that the expected file digest is always up to date, use the
    # memory hashing and create a fixture for the expected value.
    hasher = memory.SHA256(_FULL_CONTENT.encode("utf-8"))
    digest = hasher.compute()
    return digest.digest_hex


@pytest.fixture(scope="class")
def expected_header_digest():
    hasher = memory.SHA256(_HEADER.encode("utf-8"))
    digest = hasher.compute()
    return digest.digest_hex


@pytest.fixture(scope="class")
def expected_content_digest():
    hasher = memory.SHA256(_CONTENT.encode("utf-8"))
    digest = hasher.compute()
    return digest.digest_hex


class TestSimpleFileHasher:
    def test_fails_with_negative_chunk_size(self):
        with pytest.raises(ValueError, match="Chunk size must be non-negative"):
            file_hashing.SimpleFileHasher(
                _UNUSED_PATH, memory.SHA256(), chunk_size=-2
            )

    def test_hash_of_known_file(self, sample_file, expected_digest):
        hasher = file_hashing.SimpleFileHasher(sample_file, memory.SHA256())
        digest = hasher.compute()
        assert digest.digest_hex == expected_digest

    def test_hash_of_known_file_no_chunk(self, sample_file, expected_digest):
        hasher = file_hashing.SimpleFileHasher(
            sample_file, memory.SHA256(), chunk_size=0
        )
        digest = hasher.compute()
        assert digest.digest_hex == expected_digest

    def test_hash_of_known_file_small_chunk(self, sample_file, expected_digest):
        hasher = file_hashing.SimpleFileHasher(
            sample_file, memory.SHA256(), chunk_size=2
        )
        digest = hasher.compute()
        assert digest.digest_hex == expected_digest

    def test_hash_of_known_file_large_chunk(self, sample_file, expected_digest):
        size = 2 * len(_FULL_CONTENT)
        hasher = file_hashing.SimpleFileHasher(
            sample_file, memory.SHA256(), chunk_size=size
        )
        digest = hasher.compute()
        assert digest.digest_hex == expected_digest

    def test_hash_file_twice(self, sample_file):
        hasher1 = file_hashing.SimpleFileHasher(sample_file, memory.SHA256())
        digest1 = hasher1.compute()
        hasher2 = file_hashing.SimpleFileHasher(sample_file, memory.SHA256())
        digest2 = hasher2.compute()
        assert digest1.digest_value == digest2.digest_value

    def test_hash_file_twice_same_hasher(self, sample_file):
        hasher = file_hashing.SimpleFileHasher(sample_file, memory.SHA256())
        digest1 = hasher.compute()
        digest2 = hasher.compute()
        assert digest1.digest_value == digest2.digest_value

    def test_hash_file_twice_same_hasher_reset_file(self, sample_file):
        hasher = file_hashing.SimpleFileHasher(sample_file, memory.SHA256())
        digest1 = hasher.compute()
        hasher.set_file(sample_file)
        digest2 = hasher.compute()
        assert digest1.digest_value == digest2.digest_value

    def test_set_file(self, sample_file, sample_file_content_only):
        hasher = file_hashing.SimpleFileHasher(sample_file, memory.SHA256())
        digest1 = hasher.compute()
        hasher.set_file(sample_file_content_only)
        _ = hasher.compute()
        hasher.set_file(sample_file)
        digest2 = hasher.compute()
        assert digest1.digest_value == digest2.digest_value

    def test_default_digest_name(self):
        hasher = file_hashing.SimpleFileHasher(_UNUSED_PATH, memory.SHA256())
        assert hasher.digest_name == "sha256"

    def test_override_digest_name(self):
        hasher = file_hashing.SimpleFileHasher(
            _UNUSED_PATH,
            memory.SHA256(),
            chunk_size=10,
            digest_name_override="test-hash",
        )
        assert hasher.digest_name == "test-hash"

    def test_digest_algorithm_is_digest_name(self, sample_file):
        hasher = file_hashing.SimpleFileHasher(sample_file, memory.SHA256())
        digest = hasher.compute()
        assert digest.algorithm == hasher.digest_name

    def test_digest_size(self):
        memory_hasher = memory.SHA256()
        hasher = file_hashing.SimpleFileHasher(sample_file, memory_hasher)
        assert hasher.digest_size == memory_hasher.digest_size


class TestShardedFileHasher:
    def test_fails_with_negative_shard_size(self):
        with pytest.raises(
            ValueError, match="Shard size must be strictly positive"
        ):
            file_hashing.ShardedFileHasher(
                _UNUSED_PATH, memory.SHA256(), shard_size=-2, start=0, end=42
            )

    def test_fails_with_negative_start(self):
        with pytest.raises(
            ValueError, match="File start offset must be non-negative"
        ):
            file_hashing.ShardedFileHasher(
                _UNUSED_PATH, memory.SHA256(), start=-2, end=42
            )

    def test_set_fails_with_negative_start(self):
        hasher = file_hashing.ShardedFileHasher(
            _UNUSED_PATH, memory.SHA256(), start=0, end=42
        )
        with pytest.raises(
            ValueError, match="File start offset must be non-negative"
        ):
            hasher.set_shard(start=-2, end=42)

    def test_fails_with_end_lower_than_start(self):
        with pytest.raises(
            ValueError,
            match=(
                "File end offset must be stricly higher that file start offset"
            ),
        ):
            file_hashing.ShardedFileHasher(
                _UNUSED_PATH, memory.SHA256(), start=42, end=2
            )

    def test_set_fails_with_end_lower_than_start(self):
        hasher = file_hashing.ShardedFileHasher(
            _UNUSED_PATH, memory.SHA256(), start=0, end=42
        )
        with pytest.raises(
            ValueError,
            match=(
                "File end offset must be stricly higher that file start offset"
            ),
        ):
            hasher.set_shard(start=42, end=2)

    def test_fails_with_zero_read_span(self):
        with pytest.raises(
            ValueError,
            match=(
                "File end offset must be stricly higher that file start offset"
            ),
        ):
            file_hashing.ShardedFileHasher(
                _UNUSED_PATH, memory.SHA256(), start=42, end=42
            )

    def test_set_fails_with_zero_read_span(self):
        hasher = file_hashing.ShardedFileHasher(
            _UNUSED_PATH, memory.SHA256(), start=0, end=42
        )
        with pytest.raises(
            ValueError,
            match=(
                "File end offset must be stricly higher that file start offset"
            ),
        ):
            hasher.set_shard(start=42, end=42)

    def test_fails_with_read_span_too_large(self):
        with pytest.raises(
            ValueError, match="Must not read more than shard_size=2"
        ):
            file_hashing.ShardedFileHasher(
                _UNUSED_PATH, memory.SHA256(), start=0, end=42, shard_size=2
            )

    def test_set_fails_with_read_span_too_large(self):
        hasher = file_hashing.ShardedFileHasher(
            _UNUSED_PATH, memory.SHA256(), start=0, end=2, shard_size=2
        )
        with pytest.raises(
            ValueError, match="Must not read more than shard_size=2"
        ):
            hasher.set_shard(start=0, end=42)

    def test_hash_of_known_file(
        self, sample_file, expected_header_digest, expected_content_digest
    ):
        hasher1 = file_hashing.ShardedFileHasher(
            sample_file, memory.SHA256(), start=0, end=_SHARD_SIZE
        )
        hasher2 = file_hashing.ShardedFileHasher(
            sample_file, memory.SHA256(), start=_SHARD_SIZE, end=2 * _SHARD_SIZE
        )

        digest1 = hasher1.compute()
        assert digest1.digest_hex == expected_header_digest

        digest2 = hasher2.compute()
        assert digest2.digest_hex == expected_content_digest

    def test_hash_of_known_file_using_set_shard(
        self, sample_file, expected_header_digest, expected_content_digest
    ):
        hasher = file_hashing.ShardedFileHasher(
            sample_file, memory.SHA256(), start=0, end=_SHARD_SIZE
        )

        digest1 = hasher.compute()
        assert digest1.digest_hex == expected_header_digest

        hasher.set_shard(start=_SHARD_SIZE, end=2 * _SHARD_SIZE)
        digest2 = hasher.compute()
        assert digest2.digest_hex == expected_content_digest

    def test_hash_of_known_file_end_overflow(
        self, sample_file, expected_digest
    ):
        hasher = file_hashing.ShardedFileHasher(
            sample_file, memory.SHA256(), start=0, end=3 * _SHARD_SIZE
        )
        digest = hasher.compute()
        assert digest.digest_hex == expected_digest

    def test_hash_of_known_file_set_end_overflow(
        self, sample_file, expected_digest
    ):
        hasher = file_hashing.ShardedFileHasher(
            sample_file, memory.SHA256(), start=0, end=_SHARD_SIZE
        )
        hasher.set_shard(start=0, end=5 * _SHARD_SIZE)
        digest = hasher.compute()
        assert digest.digest_hex == expected_digest

    def test_hash_of_known_file_no_chunk(
        self, sample_file, expected_header_digest, expected_content_digest
    ):
        hasher1 = file_hashing.ShardedFileHasher(
            sample_file, memory.SHA256(), start=0, end=_SHARD_SIZE, chunk_size=0
        )
        hasher2 = file_hashing.ShardedFileHasher(
            sample_file,
            memory.SHA256(),
            start=_SHARD_SIZE,
            end=2 * _SHARD_SIZE,
            chunk_size=0,
        )

        digest1 = hasher1.compute()
        assert digest1.digest_hex == expected_header_digest

        digest2 = hasher2.compute()
        assert digest2.digest_hex == expected_content_digest

    def test_hash_of_known_file_small_chunk(
        self, sample_file, expected_header_digest, expected_content_digest
    ):
        hasher1 = file_hashing.ShardedFileHasher(
            sample_file, memory.SHA256(), start=0, end=_SHARD_SIZE, chunk_size=1
        )
        hasher2 = file_hashing.ShardedFileHasher(
            sample_file,
            memory.SHA256(),
            start=_SHARD_SIZE,
            end=2 * _SHARD_SIZE,
            chunk_size=1,
        )

        digest1 = hasher1.compute()
        assert digest1.digest_hex == expected_header_digest

        digest2 = hasher2.compute()
        assert digest2.digest_hex == expected_content_digest

    def test_hash_of_known_file_large_chunk(
        self, sample_file, expected_header_digest, expected_content_digest
    ):
        hasher1 = file_hashing.ShardedFileHasher(
            sample_file,
            memory.SHA256(),
            start=0,
            end=_SHARD_SIZE,
            chunk_size=2 * len(_FULL_CONTENT),
        )
        hasher2 = file_hashing.ShardedFileHasher(
            sample_file,
            memory.SHA256(),
            start=_SHARD_SIZE,
            end=2 * _SHARD_SIZE,
            chunk_size=2 * len(_FULL_CONTENT),
        )

        digest1 = hasher1.compute()
        assert digest1.digest_hex == expected_header_digest

        digest2 = hasher2.compute()
        assert digest2.digest_hex == expected_content_digest

    def test_hash_of_known_file_large_shard(
        self, sample_file, expected_header_digest, expected_content_digest
    ):
        hasher1 = file_hashing.ShardedFileHasher(
            sample_file,
            memory.SHA256(),
            start=0,
            end=_SHARD_SIZE,
            shard_size=2 * len(_FULL_CONTENT),
        )
        hasher2 = file_hashing.ShardedFileHasher(
            sample_file,
            memory.SHA256(),
            start=_SHARD_SIZE,
            end=2 * _SHARD_SIZE,
            shard_size=2 * len(_FULL_CONTENT),
        )

        digest1 = hasher1.compute()
        assert digest1.digest_hex == expected_header_digest

        digest2 = hasher2.compute()
        assert digest2.digest_hex == expected_content_digest

    def test_default_digest_name(self):
        hasher = file_hashing.ShardedFileHasher(
            _UNUSED_PATH, memory.SHA256(), start=0, end=2, shard_size=10
        )
        assert hasher.digest_name == "sha256-sharded-10"

    def test_override_digest_name(self):
        hasher = file_hashing.ShardedFileHasher(
            _UNUSED_PATH,
            memory.SHA256(),
            start=0,
            end=2,
            shard_size=10,
            digest_name_override="test-hash",
        )
        assert hasher.digest_name == "test-hash"

    def test_digest_algorithm_is_digest_name(self, sample_file):
        hasher = file_hashing.ShardedFileHasher(
            sample_file,
            memory.SHA256(),
            start=0,
            end=2,
            shard_size=10,
            digest_name_override="test-hash",
        )
        digest = hasher.compute()
        assert digest.algorithm == hasher.digest_name

    def test_digest_size(self):
        memory_hasher = memory.SHA256()
        hasher = file_hashing.ShardedFileHasher(
            sample_file, memory_hasher, start=0, end=2
        )
        assert hasher.digest_size == memory_hasher.digest_size
