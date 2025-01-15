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


"""Script for running a benchmark to pick a chunk parameter."""

import argparse
import timeit

import serialize


def build_parser() -> argparse.ArgumentParser:
    """Builds the command line parser for the chunk experiment."""
    parser = argparse.ArgumentParser(
        description="chunk size benchmark data for model signing"
    )

    parser.add_argument("path", help="path to model")

    parser.add_argument(
        "--repeat",
        help="how many times to repeat each chunk size",
        type=int,
        default=5,
    )

    parser.add_argument(
        "--sizes", help="chunk sizes to benchmark", nargs="+", type=int
    )

    return parser


def _default_sizes() -> list[int]:
    # 0 is a special value to (attempt to) read whole files into RAM
    # then powers of 2 between 1KB and 1GB
    return (
        [0] + [2**i for i in range(10, 31)]
    )  # pytype: disable=bad-return-type (https://github.com/google/pytype/issues/795)


if __name__ == "__main__":
    chunk_args = build_parser().parse_args()

    chunk_sizes = chunk_args.sizes or _default_sizes()
    padding = len(f"{max(chunk_sizes)}: ")
    for chunk_size in chunk_sizes:
        args = serialize.build_parser().parse_args(
            [chunk_args.path, f"--chunk={chunk_size}"]
        )
        times = timeit.repeat(
            lambda args=args: serialize.run(args),
            number=1,
            repeat=chunk_args.repeat,
        )
        print(f"{f'{chunk_size}: ':<{padding}}{min(times):10.4f}")
