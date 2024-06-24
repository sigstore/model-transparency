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

from model_signing.hashing import precomputed


class TestPrecomputedDigest:

    def test_compute_does_not_change_hash(self):
        hash_value = b"value"
        hasher = precomputed.PrecomputedDigest("test", hash_value)
        digest = hasher.compute()
        assert digest.digest_value == hash_value
        digest = hasher.compute()
        assert digest.digest_value == hash_value

    def test_expected_hash_and_hex(self):
        hash_value = b"abcd"
        hash_hex_value = "61626364"
        hasher = precomputed.PrecomputedDigest("test", hash_value)
        digest = hasher.compute()
        assert digest.digest_value == hash_value
        assert digest.digest_hex == hash_hex_value

    def test_expected_hash_and_hex_unicode(self):
        hash_value = "*哈¥эш希".encode("utf-8")
        hash_hex_value = "2ae59388c2a5d18dd188e5b88c"
        hasher = precomputed.PrecomputedDigest("test", hash_value)
        digest = hasher.compute()
        assert digest.digest_value == hash_value
        assert digest.digest_hex == hash_hex_value

    def test_expected_hash_type(self):
        hasher = precomputed.PrecomputedDigest("test", b"abcd")
        assert hasher.digest_name == "test"
        digest = hasher.compute()
        assert digest.algorithm == "test"

    def test_digest_size(self):
        digest = b"abcd"
        hasher = precomputed.PrecomputedDigest("test", digest)
        assert hasher.digest_size == len(digest)
