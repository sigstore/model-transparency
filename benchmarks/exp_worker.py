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


"""Script for running a benchmark to pick max_workers parameter."""

import argparse
import timeit

import serialize


def build_parser() -> argparse.ArgumentParser:
    """Builds the command line parser for the worker experiment."""
    parser = argparse.ArgumentParser(
        description="max_workers benchmark data for model signing"
    )

    parser.add_argument("path", help="path to model")

    parser.add_argument(
        "--repeat",
        help="how many times to repeat each worker count",
        type=int,
        default=5,
    )

    parser.add_argument(
        "--workers", help="number of workers to benchmark", nargs="+", type=int
    )

    return parser


def _default_workers() -> list[int]:
    return [1, 2, 4, 8, 12, 16, 24, 32, 48, 64, 80, 96, 128]


if __name__ == "__main__":
    worker_args = build_parser().parse_args()

    workers = worker_args.workers or _default_workers()
    padding = len(f"{max(workers)}: ")
    for worker in workers:
        args = serialize.build_parser().parse_args(
            [worker_args.path, f"--max_workers={worker}"]
        )
        times = timeit.repeat(
            lambda args=args: serialize.run(args),
            number=1,
            repeat=worker_args.repeat,
        )
        print(f"{f'{worker}: ':<{padding}}{min(times):10.4f}")
