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
import pathlib
import timeit

import serialize


def build_parser() -> argparse.ArgumentParser:
    """Builds the command line parser for the hash experiment."""
    parser = argparse.ArgumentParser(
        description="hash algorithm benchmark data for model signing"
    )
    parser.add_argument("path", help="path to model", type=pathlib.Path)

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
        default=["sha256", "blake2"],
    )

    return parser


if __name__ == "__main__":
    hash_args = build_parser().parse_args()
    bench_parser = serialize.build_parser()
    for algorithm in hash_args.methods:
        args = bench_parser.parse_args(
            [
                str(hash_args.path),
                "--skip_manifest",
                "--hash_method",
                algorithm,
                "--merge_hasher",
                algorithm,
            ]
        )
        times = timeit.repeat(
            lambda args=args: serialize.run(args),
            number=1,
            repeat=hash_args.repeat,
        )
        # Grab the min time, as suggested by the docs
        # https://docs.python.org/3/library/timeit.html#timeit.Timer.repeat
        print(f"algorithm: {algorithm}, best time: {min(times)}s")
