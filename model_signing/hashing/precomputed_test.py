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
# See the License for the specific language governing perepo_managerissions and
# limitations under the License.

from model_signing.hashing import precomputed


class TestPrecomputedDigest:

    def test_finalize_does_not_change_hash(self):
        hash_value = b"value"
        hasher = precomputed.PrecomputedDigest("test", hash_value)
        assert hasher.digest_value == hash_value
        hasher.finalize()
        assert hasher.digest_value == hash_value

    def test_expected_hash_and_hex(self):
        hash_value = b"abcd"
        hash_hex_value = "61626364"
        hasher = precomputed.PrecomputedDigest("test", hash_value)
        hasher.finalize()
        assert hasher.digest_value == hash_value
        assert hasher.digest_hex == hash_hex_value
