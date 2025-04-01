# Copyright (c) 2024, NVIDIA CORPORATION.  All rights reserved.
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

from model_signing._hashing import file
from model_signing._hashing import memory
from model_signing._serialization import serialize_by_file
from model_signing._serialization import serialize_by_file_shard
from model_signing.signature import fake
from model_signing.signing import in_toto
from model_signing.signing import in_toto_signature


class TestIntotoSignature:
    def _shard_hasher_factory(
        self, path: pathlib.Path, start: int, end: int
    ) -> file.ShardedFileHasher:
        return file.ShardedFileHasher(
            path, memory.SHA256(), start=start, end=end
        )

    def _hasher_factory(self, path: pathlib.Path) -> file.FileHasher:
        return file.SimpleFileHasher(path, memory.SHA256())

    def test_sign_and_verify_sharded_manifest(self, sample_model_folder):
        signer = in_toto_signature.IntotoSigner(fake.FakeSigner())
        verifier = in_toto_signature.IntotoVerifier(fake.FakeVerifier())
        shard_serializer = serialize_by_file_shard.Serializer(
            self._shard_hasher_factory, allow_symlinks=True
        )
        shard_manifest = shard_serializer.serialize(sample_model_folder)

        payload = in_toto.ShardDigestsIntotoPayload.from_manifest(
            shard_manifest
        )
        sig = signer.sign(payload)
        verifier.verify(sig)
        manifest = sig.to_manifest()
        assert shard_manifest == manifest

    def test_sign_and_verify_digest_sharded_manifest(self, sample_model_folder):
        signer = in_toto_signature.IntotoSigner(fake.FakeSigner())
        verifier = in_toto_signature.IntotoVerifier(fake.FakeVerifier())
        shard_serializer = serialize_by_file_shard.Serializer(
            self._shard_hasher_factory, allow_symlinks=True
        )
        shard_manifest = shard_serializer.serialize(sample_model_folder)

        payload = in_toto.DigestOfShardDigestsIntotoPayload.from_manifest(
            shard_manifest
        )
        sig = signer.sign(payload)
        verifier.verify(sig)
        manifest = sig.to_manifest()
        assert shard_manifest == manifest

    def test_sign_and_verify_digest_of_digest_manifest(
        self, sample_model_folder
    ):
        signer = in_toto_signature.IntotoSigner(fake.FakeSigner())
        verifier = in_toto_signature.IntotoVerifier(fake.FakeVerifier())
        file_serializer = serialize_by_file.Serializer(
            self._hasher_factory, allow_symlinks=True
        )
        file_manifest = file_serializer.serialize(sample_model_folder)

        payload = in_toto.DigestOfDigestsIntotoPayload.from_manifest(
            file_manifest
        )
        sig = signer.sign(payload)
        verifier.verify(sig)
        manifest = sig.to_manifest()
        assert file_manifest == manifest

    def test_sign_and_verify_digest_manifest(self, sample_model_folder):
        signer = in_toto_signature.IntotoSigner(fake.FakeSigner())
        verifier = in_toto_signature.IntotoVerifier(fake.FakeVerifier())
        file_serializer = serialize_by_file.Serializer(
            self._hasher_factory, allow_symlinks=True
        )
        file_manifest = file_serializer.serialize(sample_model_folder)

        payload = in_toto.DigestsIntotoPayload.from_manifest(file_manifest)
        sig = signer.sign(payload)
        verifier.verify(sig)
        manifest = sig.to_manifest()
        assert file_manifest == manifest
