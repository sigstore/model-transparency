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

from model_signing._hashing import memory


class TestSHA256:
    def test_hash_known_value(self):
        hasher = memory.SHA256(b"Test string")
        digest = hasher.compute()
        expected = (
            "a3e49d843df13c2e2a7786f6ecd7e0d184f45d718d1ac1a8a63e570466e489dd"
        )
        assert digest.digest_hex == expected

    def test_hash_update_twice_is_the_same_as_update_with_concatenation(self):
        str1 = "Test "
        str2 = "string"

        hasher1 = memory.SHA256()
        hasher1.update(str1.encode("utf-8"))
        hasher1.update(str2.encode("utf-8"))
        digest1 = hasher1.compute()

        str_all = str1 + str2
        hasher2 = memory.SHA256()
        hasher2.update(str_all.encode("utf-8"))
        digest2 = hasher2.compute()

        assert digest1.digest_hex == digest2.digest_hex
        assert digest1.digest_value == digest2.digest_value

    def test_hash_update_empty(self):
        hasher1 = memory.SHA256(b"Test string")
        hasher1.update(b"")
        digest1 = hasher1.compute()

        hasher2 = memory.SHA256(b"Test string")
        digest2 = hasher2.compute()

        assert digest1.digest_hex == digest2.digest_hex
        assert digest1.digest_value == digest2.digest_value

    def test_update_after_reset(self):
        hasher = memory.SHA256(b"Test string")
        digest1 = hasher.compute()
        hasher.reset()
        hasher.update(b"Test string")
        digest2 = hasher.compute()

        assert digest1.digest_hex == digest2.digest_hex
        assert digest1.digest_value == digest2.digest_value

    def test_digest_size(self):
        hasher = memory.SHA256(b"Test string")
        assert hasher.digest_size == 32

        digest = hasher.compute()
        assert digest.digest_size == 32


class TestBLAKE2:
    def test_hash_known_value(self):
        hasher = memory.BLAKE2(b"Test string")
        digest = hasher.compute()
        expected = (
            "3f1b20a13e94ef2a12c50f40de256e0eb444f274b8e2e04e5fb3f572242c858a"
            "f600a06a0c350eef1645307a9bf2fa1fcb65445a0b3b2b44d0602ab95f4fb802"
        )
        assert digest.digest_hex == expected

    def test_hash_update_twice_is_the_same_as_update_with_concatenation(self):
        str1 = "Test "
        str2 = "string"

        hasher1 = memory.BLAKE2()
        hasher1.update(str1.encode("utf-8"))
        hasher1.update(str2.encode("utf-8"))
        digest1 = hasher1.compute()

        str_all = str1 + str2
        hasher2 = memory.BLAKE2()
        hasher2.update(str_all.encode("utf-8"))
        digest2 = hasher2.compute()

        assert digest1.digest_hex == digest2.digest_hex
        assert digest1.digest_value == digest2.digest_value

    def test_hash_update_empty(self):
        hasher1 = memory.BLAKE2(b"Test string")
        hasher1.update(b"")
        digest1 = hasher1.compute()

        hasher2 = memory.BLAKE2(b"Test string")
        digest2 = hasher2.compute()

        assert digest1.digest_hex == digest2.digest_hex
        assert digest1.digest_value == digest2.digest_value

    def test_update_after_reset(self):
        hasher = memory.BLAKE2(b"Test string")
        digest1 = hasher.compute()
        hasher.reset()
        hasher.update(b"Test string")
        digest2 = hasher.compute()

        assert digest1.digest_hex == digest2.digest_hex
        assert digest1.digest_value == digest2.digest_value

    def test_digest_size(self):
        hasher = memory.BLAKE2(b"Test string")
        assert hasher.digest_size == 64

        digest = hasher.compute()
        assert digest.digest_size == 64


class TestBLAKE3:
    def test_hash_known_value(self):
        hasher = memory.BLAKE3(b"Test string")
        digest = hasher.compute()
        expected = (
            "f3adfd721502f7d9510368688a392ab4f29dbff47092c0aea25f638d4985a8b1"
        )
        assert digest.digest_hex == expected

    def test_hash_update_twice_is_the_same_as_update_with_concatenation(self):
        str1 = "Test "
        str2 = "string"

        hasher1 = memory.BLAKE3()
        hasher1.update(str1.encode("utf-8"))
        hasher1.update(str2.encode("utf-8"))
        digest1 = hasher1.compute()

        str_all = str1 + str2
        hasher2 = memory.BLAKE3()
        hasher2.update(str_all.encode("utf-8"))
        digest2 = hasher2.compute()

        assert digest1.digest_hex == digest2.digest_hex
        assert digest1.digest_value == digest2.digest_value

    def test_hash_update_empty(self):
        hasher1 = memory.BLAKE3(b"Test string")
        hasher1.update(b"")
        digest1 = hasher1.compute()

        hasher2 = memory.BLAKE3(b"Test string")
        digest2 = hasher2.compute()

        assert digest1.digest_hex == digest2.digest_hex
        assert digest1.digest_value == digest2.digest_value

    def test_update_after_reset(self):
        hasher = memory.BLAKE3(b"Test string")
        digest1 = hasher.compute()
        hasher.reset()
        hasher.update(b"Test string")
        digest2 = hasher.compute()

        assert digest1.digest_hex == digest2.digest_hex
        assert digest1.digest_value == digest2.digest_value

    def test_digest_size(self):
        hasher = memory.BLAKE3(b"Test string")
        assert hasher.digest_size == 32

        digest = hasher.compute()
        assert digest.digest_size == 32
