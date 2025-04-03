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

from model_signing._hashing import io
from model_signing._hashing import memory
from model_signing._serialization import file
from model_signing.signature import fake
from model_signing.signing import in_toto_signature
from model_signing.signing import signing


class TestIntotoSignature:
    def _hasher_factory(self, path: pathlib.Path) -> io.FileHasher:
        return io.SimpleFileHasher(path, memory.SHA256())

    def test_sign_and_verify_digest_manifest(self, sample_model_folder):
        signer = in_toto_signature.IntotoSigner(fake.FakeSigner())
        verifier = in_toto_signature.IntotoVerifier(fake.FakeVerifier())
        file_serializer = file.Serializer(
            self._hasher_factory, allow_symlinks=True
        )
        file_manifest = file_serializer.serialize(sample_model_folder)

        payload = signing.Payload(file_manifest)
        sig = signer.sign(payload)
        verifier.verify(sig)
        manifest = sig.to_manifest()
        assert file_manifest == manifest

    def test_signature_round_trip(self, sample_model_folder, tmp_path):
        signer = in_toto_signature.IntotoSigner(fake.FakeSigner())
        file_serializer = file.Serializer(
            self._hasher_factory, allow_symlinks=True
        )
        file_manifest = file_serializer.serialize(sample_model_folder)

        payload = signing.Payload(file_manifest)
        sig = signer.sign(payload)
        sig_file = tmp_path / "sig"
        sig.write(sig_file)
        sig2 = in_toto_signature.IntotoSignature.read(sig_file)
        assert sig.to_manifest() == sig2.to_manifest()
