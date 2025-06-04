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


"""Script for running a benchmark to compare a memory vs disk hasher."""

import argparse
import os
import pathlib
import time
from typing import Final

import generate
import numpy as np
from typing_extensions import override

from model_signing._hashing import hashing
from model_signing._hashing import io
from model_signing._hashing import memory


KB: Final[int] = 1024
MB: Final[int] = 1024 * KB
GB: Final[int] = 1024 * MB


def build_parser() -> argparse.ArgumentParser:
    """Builds the parser for the disk vs memory hasher experiment."""
    parser = argparse.ArgumentParser(
        description="disk vs memory hasher benchmark data for model signing"
    )

    parser.add_argument(
        "path", help="path to create temporary model (deleted on completion)"
    )

    parser.add_argument(
        "--repeat",
        help="how many times to repeat each experiment",
        type=int,
        default=5,
    )

    parser.add_argument(
        "--data-sizes", help="model file sizes to generate", nargs="+", type=int
    )

    return parser


def _default_sizes() -> list[int]:
    """Generates sizes following 1, 2, 5 pattern, useful for log scale.

    Small sizes are omitted due to effects of disk caching.
    """
    return [1 * GB, 2 * GB, 5 * GB, 10 * GB, 20 * GB, 50 * GB]


class TimedFileHasher(io.SimpleFileHasher):
    """Simple file hash engine that measures the time to compute the digest."""

    @override
    def compute(self) -> hashing.Digest:
        self._hash_time_ns = 0
        self._read_time_ns = 0
        self._content_hasher.reset()

        # ignoring special case where chunk_size is 0
        with open(self._file, "rb") as f:
            while True:
                start = time.perf_counter_ns()
                data = f.read(self._chunk_size)
                end = time.perf_counter_ns()
                self._read_time_ns += end - start
                if not data:
                    break
                start = time.perf_counter_ns()
                self._content_hasher.update(data)
                end = time.perf_counter_ns()
                self._hash_time_ns += end - start

        start = time.perf_counter_ns()
        digest = self._content_hasher.compute()
        end = time.perf_counter_ns()
        self._hash_time_ns += end - start
        return hashing.Digest(self.digest_name, digest.digest_value)

    @property
    def read_time(self) -> float:
        """Returns time spent (s) reading a file into memory."""
        return self._read_time_ns / 1e9

    @property
    def hash_time(self) -> float:
        """Returns time spent (s) hashing bytes already in memory."""
        return self._hash_time_ns / 1e9


if __name__ == "__main__":
    np.random.seed(42)
    args = build_parser().parse_args()
    sizes = args.data_sizes or _default_sizes()
    padding = len(str(max(sizes)))
    hasher = TimedFileHasher(pathlib.Path(args.path), memory.SHA256())

    print(f"{'Size (B)':{padding}} {'Memory (s)':>10} {'Disk (s)':>10}")
    for size in sizes:
        generate.create_file_of_given_size(args.path, size)
        memory_times = []
        disk_times = []
        for _ in range(args.repeat):
            hasher.compute()
            memory_times.append(hasher.hash_time)
            disk_times.append(hasher.hash_time + hasher.read_time)

        mem_t = min(memory_times)
        disk_t = min(disk_times)
        print(f"{f'{size}':<{padding}} {mem_t:10.4f} {disk_t:10.4f}")
    os.remove(args.path)
