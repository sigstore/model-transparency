# Copyright 2025 The Sigstore Authors
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


"""Script for running a benchmark to pick a hashing algorithm."""

import argparse
import timeit
from typing import Final

import numpy as np

from model_signing._hashing import hashing
from model_signing._hashing import memory


KB: Final[int] = 1024
MB: Final[int] = 1024 * KB
GB: Final[int] = 1024 * MB


def build_parser() -> argparse.ArgumentParser:
    """Builds the command line parser for the hash experiment."""
    parser = argparse.ArgumentParser(
        description="hash algorithm benchmark data for model signing"
    )

    parser.add_argument(
        "--repeat",
        help="how many times to repeat each algorithm",
        type=int,
        default=5,
    )

    parser.add_argument(
        "--methods",
        help="hash methods to benchmark",
        nargs="+",
        type=str,
        default=["sha256", "blake2", "blake3"],
    )

    parser.add_argument(
        "--data-sizes", help="hash methods to benchmark", nargs="+", type=int
    )

    return parser


def _human_size(size: int) -> str:
    if size >= GB:
        return str(size / GB) + " GB"
    elif size >= MB:
        return str(size / MB) + " MB"
    elif size >= KB:
        return str(size / KB) + " KB"
    return str(size) + " B"


def _get_hasher(hash_algorithm: str) -> hashing.StreamingHashEngine:
    match hash_algorithm:
        case "sha256":
            return memory.SHA256()
        case "blake2":
            return memory.BLAKE2()
        case "blake3":
            return memory.BLAKE3()
        case _:
            raise ValueError(
                f"Cannot convert {hash_algorithm} to a hash engine"
            )


def _generate_data(size: int) -> bytes:
    if size < 0:
        raise ValueError("Cannot generate negative bytes")
    return np.random.randint(0, 256, size, dtype=np.uint8).tobytes()


def _default_sizes() -> list[int]:
    """Generates sizes following 1, 2, 5 pattern, useful for log scale."""
    sizes = []
    for scale in [KB, MB, GB]:
        for d in [1, 2, 5, 10, 20, 50, 100, 200, 500]:
            if scale == GB and d > 20:
                break
            sizes.append(d * scale)
    return sizes


def _get_padding(methods: list[str], sizes: list[int]) -> int:
    """Calculates the necessary padding by looking at longest output.

    E.g. "sha256/1024: " would require 13 characters of padding.
    """
    return len(f"{max(methods, key=len)}/{max(sizes)}: ")


if __name__ == "__main__":
    np.random.seed(42)
    args = build_parser().parse_args()
    sizes = args.data_sizes or _default_sizes()
    padding = _get_padding(args.methods, sizes)

    for size in sizes:
        data = _generate_data(size)
        for algorithm in args.methods:
            hasher = _get_hasher(algorithm)

            def hash(hasher=hasher, data=data):
                hasher.update(data)
                return hasher.compute()

            times = timeit.repeat(lambda: hash(), number=1, repeat=args.repeat)

            # Grab the min time, as suggested by the docs
            # https://docs.python.org/3/library/timeit.html#timeit.Timer.repeat
            measurement = min(times)
            print(f"{f'{algorithm}/{size}: ':<{padding}}{measurement:10.4f}")
