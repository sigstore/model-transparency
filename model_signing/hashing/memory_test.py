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

from model_signing.hashing import memory


class TestPrecomputedDigest:

    def test_hash_known_value(self):
        hasher = memory.SHA256(b"Test string")
        hasher.compute()
        expected = (
            "a3e49d843df13c2e2a7786f6ecd7e0d184f45d718d1ac1a8a63e570466e489dd"
        )
        assert hasher.digest_hex == expected

    def test_hash_update_twice_is_the_same_as_update_with_concatenation(self):
        str1 = "Test "
        str2 = "string"

        hasher1 = memory.SHA256()
        hasher1.update(str1.encode("utf-8"))
        hasher1.update(str2.encode("utf-8"))
        hasher1.compute()

        str_all = str1 + str2
        hasher2 = memory.SHA256()
        hasher2.update(str_all.encode("utf-8"))
        hasher2.compute()

        assert hasher1.digest_hex == hasher2.digest_hex
        assert hasher1.digest_value == hasher2.digest_value

    def test_hash_update_empty(self):
        hasher1 = memory.SHA256(b"Test string")
        hasher1.update(b"")
        hasher1.compute()

        hasher2 = memory.SHA256(b"Test string")
        hasher2.compute()

        assert hasher1.digest_hex == hasher2.digest_hex
        assert hasher1.digest_value == hasher2.digest_value
