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
import csv
import dataclasses
import statistics
import sys
import timeit
from pathlib import Path
from typing import Final

import numpy as np

from model_signing._hashing import hashing
from model_signing._hashing import memory


KB: Final[int] = 1024
MB: Final[int] = 1024 * KB
GB: Final[int] = 1024 * MB


@dataclasses.dataclass
class BenchmarkResult:
    """Stores timing results for a single algorithm/size combination."""

    algorithm: str
    size: int
    times: list[float]

    @property
    def min_time(self) -> float:
        """Returns the minimum (best) observed time in seconds."""
        return min(self.times)

    @property
    def mean_time(self) -> float:
        """Returns the mean observed time in seconds."""
        return statistics.mean(self.times)

    @property
    def stdev_time(self) -> float:
        """Returns the standard deviation of observed times in seconds."""
        return statistics.stdev(self.times) if len(self.times) > 1 else 0.0

    @property
    def throughput_mb_s(self) -> float:
        """Returns throughput in MB/s based on the minimum (best) time."""
        if self.min_time <= 0:
            return 0.0
        return (self.size / MB) / self.min_time


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
        "--warmup",
        help="number of warmup runs before timing (default: 1)",
        type=int,
        default=1,
    )

    parser.add_argument(
        "--methods",
        help="hash methods to benchmark",
        nargs="+",
        type=str,
        default=["sha256", "blake2", "blake3"],
    )

    parser.add_argument(
        "--data-sizes", help="data sizes to benchmark in bytes", nargs="+", type=int
    )

    parser.add_argument(
        "--output",
        help="path to write CSV results (e.g. results.csv)",
        type=Path,
        default=None,
    )

    parser.add_argument(
        "--stats",
        help="show mean and stdev alongside min time",
        action="store_true",
        default=False,
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


def _run_benchmark(
    algorithm: str,
    data: bytes,
    size: int,
    repeat: int,
    warmup: int,
) -> BenchmarkResult:
    """Runs timing for a single algorithm and data size.

    Performs warmup runs first (discarded), then measures repeat timed runs.
    Returns a BenchmarkResult with all observed times.
    """
    hasher = _get_hasher(algorithm)

    def hash_once(
        hasher: hashing.StreamingHashEngine = hasher, data: bytes = data
    ) -> hashing.Digest:
        hasher.update(data)
        return hasher.compute()

    for _ in range(warmup):
        hash_once()

    # Grab min time as suggested by the timeit docs:
    # https://docs.python.org/3/library/timeit.html#timeit.Timer.repeat
    times = timeit.repeat(lambda: hash_once(), number=1, repeat=repeat)
    return BenchmarkResult(algorithm=algorithm, size=size, times=times)


def _write_csv(results: list[BenchmarkResult], output_path: Path) -> None:
    """Writes benchmark results to a CSV file.

    Columns: algorithm, size_bytes, min_s, mean_s, stdev_s, throughput_mb_s.
    """
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["algorithm", "size_bytes", "min_s", "mean_s", "stdev_s", "throughput_mb_s"]
        )
        for r in results:
            writer.writerow([
                r.algorithm,
                r.size,
                f"{r.min_time:.6f}",
                f"{r.mean_time:.6f}",
                f"{r.stdev_time:.6f}",
                f"{r.throughput_mb_s:.2f}",
            ])


def _print_summary(results: list[BenchmarkResult], methods: list[str]) -> None:
    """Prints a peak throughput (MB/s) summary table grouped by data size."""
    print("\nSummary: peak throughput (MB/s)")
    col_width = max(len(m) for m in methods) + 2
    header = "".join(f"{m:>{col_width}}" for m in methods)
    print(f"{'':>12}{header}")

    sizes = sorted(set(r.size for r in results))
    by_key = {(r.algorithm, r.size): r for r in results}
    for size in sizes:
        row = f"{_human_size(size):>12}"
        for method in methods:
            result = by_key.get((method, size))
            if result:
                row += f"{result.throughput_mb_s:>{col_width}.1f}"
            else:
                row += f"{'N/A':>{col_width}}"
        print(row)


if __name__ == "__main__":
    np.random.seed(42)
    args = build_parser().parse_args()
    sizes = args.data_sizes or _default_sizes()
    padding = _get_padding(args.methods, sizes)

    all_results: list[BenchmarkResult] = []

    if args.stats:
        print(f"{'key':<{padding}} {'min (s)':>10} {'mean (s)':>10} {'stdev (s)':>10} {'MB/s':>10}")
    else:
        print(f"{'key':<{padding}} {'min (s)':>10} {'MB/s':>10}")

    for size in sizes:
        data = _generate_data(size)
        for algorithm in args.methods:
            result = _run_benchmark(algorithm, data, size, args.repeat, args.warmup)
            all_results.append(result)

            key = f"{algorithm}/{size}: "
            if args.stats:
                print(
                    f"{key:<{padding}} {result.min_time:10.4f}"
                    f" {result.mean_time:10.4f}"
                    f" {result.stdev_time:10.4f}"
                    f" {result.throughput_mb_s:10.1f}"
                )
            else:
                print(f"{key:<{padding}} {result.min_time:10.4f} {result.throughput_mb_s:10.1f}")

    _print_summary(all_results, args.methods)

    if args.output:
        _write_csv(all_results, args.output)
        print(f"\nResults written to {args.output}", file=sys.stderr)
