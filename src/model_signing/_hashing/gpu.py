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
"""GPU-enabled hashing engines.

This module contains hashing engines backed by PyTorch. When a CUDA capable
GPU is available, the hashing computation runs on the GPU. Otherwise, the
implementation gracefully falls back to CPU execution while exposing the same
API.

The hashing algorithm implemented is SHA256 and mirrors the one from
:mod:`hashlib`. The implementation is self-contained and relies only on basic
PyTorch tensor operations, making it suitable for execution on both CPU and
GPU devices.
"""

from __future__ import annotations

<<<<<<< ours
import torch
=======
import importlib
from typing import Any

>>>>>>> theirs
from typing_extensions import override

from model_signing._hashing import hashing


# PyTorch lacks bitwise shifts for unsigned tensors, so we operate on int64 and
# mask values to 32 bits explicitly.
# NOTE: `_MASK32` is a Python integer so that it can be broadcast on any device
# without an explicit copy.
_MASK32 = 0xFFFFFFFF


<<<<<<< ours
def _rotr(x: torch.Tensor, n: int) -> torch.Tensor:
=======
_K_VALUES = [
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
]


_H0_VALUES = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]


_TORCH: Any | None = None


def _ensure_torch() -> Any:
    """Import :mod:`torch` on demand."""
    global _TORCH
    if _TORCH is None:
        try:
            _TORCH = importlib.import_module("torch")
        except ModuleNotFoundError as exc:
            raise ModuleNotFoundError(
                "TorchSHA256 requires the optional 'torch' dependency; install "
                "with `pip install model-signing[gpu]`"
            ) from exc
    return _TORCH


def _rotr(x: Any, n: int, torch: Any) -> Any:
>>>>>>> theirs
    """Right rotation for 32-bit tensors."""
    return ((x >> n) | (x << (32 - n))) & _MASK32


<<<<<<< ours
_K = torch.tensor(
    [
        0x428A2F98,
        0x71374491,
        0xB5C0FBCF,
        0xE9B5DBA5,
        0x3956C25B,
        0x59F111F1,
        0x923F82A4,
        0xAB1C5ED5,
        0xD807AA98,
        0x12835B01,
        0x243185BE,
        0x550C7DC3,
        0x72BE5D74,
        0x80DEB1FE,
        0x9BDC06A7,
        0xC19BF174,
        0xE49B69C1,
        0xEFBE4786,
        0x0FC19DC6,
        0x240CA1CC,
        0x2DE92C6F,
        0x4A7484AA,
        0x5CB0A9DC,
        0x76F988DA,
        0x983E5152,
        0xA831C66D,
        0xB00327C8,
        0xBF597FC7,
        0xC6E00BF3,
        0xD5A79147,
        0x06CA6351,
        0x14292967,
        0x27B70A85,
        0x2E1B2138,
        0x4D2C6DFC,
        0x53380D13,
        0x650A7354,
        0x766A0ABB,
        0x81C2C92E,
        0x92722C85,
        0xA2BFE8A1,
        0xA81A664B,
        0xC24B8B70,
        0xC76C51A3,
        0xD192E819,
        0xD6990624,
        0xF40E3585,
        0x106AA070,
        0x19A4C116,
        0x1E376C08,
        0x2748774C,
        0x34B0BCB5,
        0x391C0CB3,
        0x4ED8AA4A,
        0x5B9CCA4F,
        0x682E6FF3,
        0x748F82EE,
        0x78A5636F,
        0x84C87814,
        0x8CC70208,
        0x90BEFFFA,
        0xA4506CEB,
        0xBEF9A3F7,
        0xC67178F2,
    ],
    dtype=torch.int64,
)


_H0 = torch.tensor(
    [
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    ],
    dtype=torch.int64,
)


def _sha256_torch(data: bytes, device: torch.device) -> bytes:
    """Pure PyTorch SHA256 implementation."""
=======
def _sha256_torch(data: bytes, device: Any) -> bytes:
    """Pure PyTorch SHA256 implementation."""
    torch = _ensure_torch()
>>>>>>> theirs
    msg = bytearray(data)
    bit_len = (len(msg) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while (len(msg) * 8) % 512 != 448:
        msg.append(0)
    msg.extend(bit_len.to_bytes(8, "big"))

    words = torch.tensor(
        [int.from_bytes(msg[i : i + 4], "big") for i in range(0, len(msg), 4)],
        dtype=torch.int64,
        device=device,
    )

<<<<<<< ours
    K = _K.to(device)
    h = _H0.to(device)
=======
    k = torch.tensor(_K_VALUES, dtype=torch.int64, device=device)
    h = torch.tensor(_H0_VALUES, dtype=torch.int64, device=device)
>>>>>>> theirs
    for chunk_start in range(0, words.shape[0], 16):
        w = torch.zeros(64, dtype=torch.int64, device=device)
        w[:16] = words[chunk_start : chunk_start + 16]
        for i in range(16, 64):
<<<<<<< ours
            s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
=======
            s0 = (
                _rotr(w[i - 15], 7, torch)
                ^ _rotr(w[i - 15], 18, torch)
                ^ (w[i - 15] >> 3)
            )
            s1 = (
                _rotr(w[i - 2], 17, torch)
                ^ _rotr(w[i - 2], 19, torch)
                ^ (w[i - 2] >> 10)
            )
>>>>>>> theirs
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & _MASK32

        a, b, c, d, e, f, g, hv = h
        for i in range(64):
<<<<<<< ours
            s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            ch = (e & f) ^ (((~e) & _MASK32) & g)
            temp1 = (hv + s1 + ch + K[i] + w[i]) & _MASK32
            s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
=======
            s1 = _rotr(e, 6, torch) ^ _rotr(e, 11, torch) ^ _rotr(e, 25, torch)
            ch = (e & f) ^ (((~e) & _MASK32) & g)
            temp1 = (hv + s1 + ch + k[i] + w[i]) & _MASK32
            s0 = _rotr(a, 2, torch) ^ _rotr(a, 13, torch) ^ _rotr(a, 22, torch)
>>>>>>> theirs
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & _MASK32

            hv = g
            g = f
            f = e
            e = (d + temp1) & _MASK32
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & _MASK32

        h = (h + torch.stack([a, b, c, d, e, f, g, hv])) & _MASK32

    return b"".join(int(x.item()).to_bytes(4, "big") for x in h)


class TorchSHA256(hashing.StreamingHashEngine):
    """SHA256 hashing engine powered by PyTorch."""

<<<<<<< ours
    def __init__(
        self,
        initial_data: bytes = b"",
        device: str | torch.device | None = None,
    ):
=======
    def __init__(self, initial_data: bytes = b"", device: Any | None = None):
        torch = _ensure_torch()
>>>>>>> theirs
        self._buffer = bytearray(initial_data)
        if device is None:
            device = torch.device(
                "cuda" if torch.cuda.is_available() else "cpu"
            )
        self._device = torch.device(device)

    @override
    def update(self, data: bytes) -> None:
        self._buffer.extend(data)

    @override
    def reset(self, data: bytes = b"") -> None:
        self._buffer = bytearray(data)

    @override
    def compute(self) -> hashing.Digest:
        digest_bytes = _sha256_torch(bytes(self._buffer), self._device)
        return hashing.Digest(self.digest_name, digest_bytes)

    @property
    @override
    def digest_name(self) -> str:
        return "sha256"

    @property
    @override
    def digest_size(self) -> int:
        return 32
