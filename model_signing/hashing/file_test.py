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

import pytest

from model_signing.hashing import file
from model_signing.hashing import memory


# some constants used throughout testing
_HEADER: str = "Some "
_CONTENT: str = "text."  # note that these have the same length
_FULL_CONTENT = _HEADER + _CONTENT
_SHARD_SIZE = len(_HEADER)


@pytest.fixture(scope="session")
def sample_file(tmp_path_factory):
    file_path = tmp_path_factory.mktemp("dir") / "text.txt"
    file_path.write_text(_FULL_CONTENT)
    return file_path


@pytest.fixture(scope="session")
def sample_file_content_only(tmp_path_factory):
    file_path = tmp_path_factory.mktemp("dir") / "text.txt"
    file_path.write_text(_CONTENT)
    return file_path


@pytest.fixture(scope="session")
def expected_digest():
    # To ensure that the expected file digest is always up to date, use the
    # memory hashing and create a fixture for the expected value.
    hasher = memory.SHA256(_FULL_CONTENT.encode("utf-8"))
    digest = hasher.compute()
    return digest.digest_hex


@pytest.fixture(scope="session")
def expected_header_digest():
    hasher = memory.SHA256(_HEADER.encode("utf-8"))
    digest = hasher.compute()
    return digest.digest_hex


@pytest.fixture(scope="session")
def expected_content_digest():
    hasher = memory.SHA256(_CONTENT.encode("utf-8"))
    digest = hasher.compute()
    return digest.digest_hex


class TestFileHasher:

    def test_fails_with_negative_chunk_size(self):
        with pytest.raises(ValueError, match="Chunk size must be non-negative"):
            file.FileHasher(memory.SHA256(), chunk_size=-2)

    def test_hash_of_known_file(self, sample_file, expected_digest):
        hasher = file.FileHasher(memory.SHA256())
        hasher.set_file(sample_file)
        digest = hasher.compute()
        assert digest.digest_hex == expected_digest

    def test_hash_of_known_file_no_chunk(self, sample_file, expected_digest):
        hasher = file.FileHasher(memory.SHA256(), chunk_size=0)
        hasher.set_file(sample_file)
        digest = hasher.compute()
        assert digest.digest_hex == expected_digest

    def test_hash_of_known_file_small_chunk(self, sample_file, expected_digest):
        hasher = file.FileHasher(memory.SHA256(), chunk_size=2)
        hasher.set_file(sample_file)
        digest = hasher.compute()
        assert digest.digest_hex == expected_digest

    def test_hash_file_twice(self, sample_file):
        hasher1 = file.FileHasher(memory.SHA256())
        hasher1.set_file(sample_file)
        digest1 = hasher1.compute()
        hasher2 = file.FileHasher(memory.SHA256())
        hasher2.set_file(sample_file)
        digest2 = hasher2.compute()
        assert digest1.digest_value == digest2.digest_value

    def test_hash_file_twice_same_hasher(self, sample_file):
        hasher = file.FileHasher(memory.SHA256())
        hasher.set_file(sample_file)
        digest1 = hasher.compute()
        digest2 = hasher.compute()
        assert digest1.digest_value == digest2.digest_value

    def test_set_file(self, sample_file, sample_file_content_only):
        hasher = file.FileHasher(memory.SHA256())
        hasher.set_file(sample_file)
        digest1 = hasher.compute()
        hasher.set_file(sample_file_content_only)
        _ = hasher.compute()
        hasher.set_file(sample_file)
        digest2 = hasher.compute()
        assert digest1.digest_value == digest2.digest_value

    def test_default_digest_name(self):
        hasher = file.FileHasher(memory.SHA256(), chunk_size=10)
        assert hasher.digest_name == "file-sha256"

    def test_override_digest_name(self):
        hasher = file.FileHasher(
            memory.SHA256(),
            chunk_size=10,
            digest_name_override="test-hash",
        )
        assert hasher.digest_name == "test-hash"

    def test_digest_algorithm_is_digest_name(self, sample_file):
        hasher = file.FileHasher(memory.SHA256())
        hasher.set_file(sample_file)
        digest = hasher.compute()
        assert digest.algorithm == hasher.digest_name


class TestShardedFileHasher:

    def test_fails_with_negative_shard_size(self):
        with pytest.raises(
            ValueError, match="Shard size must be strictly positive"
        ):
            file.ShardedFileHasher(memory.SHA256(), shard_size=-2)

    def test_fails_with_negative_start(self):
        hasher = file.ShardedFileHasher(memory.SHA256())
        with pytest.raises(
            ValueError, match="File start offset must be non-negative"
        ):
            hasher.set_file_shard("unused", start=-2, end=42)

    def test_fails_with_end_lower_than_start(self):
        hasher = file.ShardedFileHasher(memory.SHA256())
        with pytest.raises(
            ValueError,
            match=(
                "File end offset must be stricly higher that file start offset"
            ),
        ):
            hasher.set_file_shard("unused", start=42, end=2)

    #def test_fails_with_zero_read_span(self):
    #    with pytest.raises(
    #        ValueError,
    #        match=(
    #            "File end offset must be stricly higher that file start offset"
    #        ),
    #    ):
    #        file.ShardedFileHasher("unused", memory.SHA256(), start=2, end=2)

    #def test_fails_with_read_span_too_large(self):
    #    with pytest.raises(
    #        ValueError, match="Must not read more than shard_size=2"
    #    ):
    #        file.ShardedFileHasher(
    #            "unused", memory.SHA256(), start=0, end=42, shard_size=2
    #        )

    #def test_hash_of_known_file(
    #    self, sample_file, expected_header_digest, expected_content_digest
    #):
    #    hasher1 = file.ShardedFileHasher(
    #        sample_file, memory.SHA256(), start=0, end=_SHARD_SIZE
    #    )
    #    hasher2 = file.ShardedFileHasher(
    #        sample_file, memory.SHA256(), start=_SHARD_SIZE, end=2 * _SHARD_SIZE
    #    )

    #    hasher1.compute()
    #    assert hasher1.digest_hex == expected_header_digest

    #    hasher2.compute()
    #    assert hasher2.digest_hex == expected_content_digest

    #def test_hash_of_known_file_no_chunk(
    #    self, sample_file, expected_header_digest, expected_content_digest
    #):
    #    hasher1 = file.ShardedFileHasher(
    #        sample_file, memory.SHA256(), start=0, end=_SHARD_SIZE, chunk_size=0
    #    )
    #    hasher2 = file.ShardedFileHasher(
    #        sample_file,
    #        memory.SHA256(),
    #        start=_SHARD_SIZE,
    #        end=2 * _SHARD_SIZE,
    #        chunk_size=0,
    #    )

    #    hasher1.compute()
    #    assert hasher1.digest_hex == expected_header_digest

    #    hasher2.compute()
    #    assert hasher2.digest_hex == expected_content_digest

    #def test_hash_of_known_file_small_chunk(
    #    self, sample_file, expected_header_digest, expected_content_digest
    #):
    #    hasher1 = file.ShardedFileHasher(
    #        sample_file, memory.SHA256(), start=0, end=_SHARD_SIZE, chunk_size=1
    #    )
    #    hasher2 = file.ShardedFileHasher(
    #        sample_file,
    #        memory.SHA256(),
    #        start=_SHARD_SIZE,
    #        end=2 * _SHARD_SIZE,
    #        chunk_size=1,
    #    )

    #    hasher1.compute()
    #    assert hasher1.digest_hex == expected_header_digest

    #    hasher2.compute()
    #    assert hasher2.digest_hex == expected_content_digest

    #def test_default_digest_name(self):
    #    hasher = file.ShardedFileHasher(
    #        "unused", memory.SHA256(), start=0, end=2, shard_size=10
    #    )
    #    assert hasher.digest_name == "file-sha256-10"

    #def test_override_digest_name(self):
    #    hasher = file.ShardedFileHasher(
    #        "unused",
    #        memory.SHA256(),
    #        start=0,
    #        end=2,
    #        shard_size=10,
    #        digest_name_override="test-hash",
    #    )
    #    assert hasher.digest_name == "test-hash"
