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
import sys

import pytest
from typing_extensions import override

from model_signing.hashing import hashing
from model_signing.manifest import manifest
from model_signing.signing import empty_signing
from model_signing.signing import signing
from tests import test_support


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


class TestEmptySigningPayload:
    def test_build_from_digest_manifest(self):
        digest = hashing.Digest("test", b"test_digest")
        manifest_file = manifest.DigestManifest(digest)

        payload = empty_signing.EmptySigningPayload.from_manifest(manifest_file)

        assert payload == empty_signing.EmptySigningPayload()

    def test_build_from_itemized_manifest(self):
        path1 = pathlib.PurePath("file1")
        digest1 = hashing.Digest("test", b"abcd")
        item1 = manifest.FileManifestItem(path=path1, digest=digest1)

        path2 = pathlib.PurePath("file2")
        digest2 = hashing.Digest("test", b"efgh")
        item2 = manifest.FileManifestItem(path=path2, digest=digest2)

        manifest_file = manifest.FileLevelManifest([item1, item2])
        payload = empty_signing.EmptySigningPayload.from_manifest(manifest_file)

        assert payload == empty_signing.EmptySigningPayload()


class TestEmptySignature:
    def test_write_and_read(self):
        signature = empty_signing.EmptySignature()
        signature.write(test_support.UNUSED_PATH)

        new_signature = empty_signing.EmptySignature.read(
            test_support.UNUSED_PATH
        )

        assert new_signature == signature


class TestEmptySigner:
    def test_sign_gives_empty_signature(self):
        payload = empty_signing.EmptySigningPayload()
        signer = empty_signing.EmptySigner()

        signature = signer.sign(payload)

        assert isinstance(signature, empty_signing.EmptySignature)


class _FakeSignature(signing.Signature):
    """A test only signature that does nothing."""

    @override
    def write(self, path: pathlib.Path) -> None:
        del path  # unused, do nothing

    @classmethod
    @override
    def read(cls, path: pathlib.Path) -> Self:
        del path  # unused, do nothing
        return cls()


class TestEmptyVerifier:
    def test_only_empty_signatures_allowed(self):
        signature = _FakeSignature()
        verifier = empty_signing.EmptyVerifier()

        with pytest.raises(
            TypeError, match="Only `EmptySignature` instances are supported"
        ):
            verifier.verify(signature)

    def test_verification_always_fails(self):
        signature = empty_signing.EmptySignature()
        verifier = empty_signing.EmptyVerifier()

        with pytest.raises(ValueError, match="Signature verification failed"):
            verifier.verify(signature)
