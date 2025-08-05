"""Tests for GPU backed hashing engines."""

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

from model_signing._hashing.gpu import TorchSHA256
from model_signing._hashing.memory import SHA256


pytest.importorskip("torch")


def test_torch_sha256_matches_hashlib():
    data = b"sigstore"
    gpu_hasher = TorchSHA256(data)
    cpu_hasher = SHA256(data)
    gpu_digest = gpu_hasher.compute()
    cpu_digest = cpu_hasher.compute()
    assert gpu_digest.digest_value == cpu_digest.digest_value
    assert gpu_digest.algorithm == cpu_digest.algorithm == "sha256"
