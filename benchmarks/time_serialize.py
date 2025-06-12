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


"""Script for timing model serialization benchmarks."""

import argparse
import json
import sys
import time

import cpuinfo
import psutil
import serialize


def build_parser() -> argparse.ArgumentParser:
    """Builds the command line parser to benchmark serializing models."""
    parser = argparse.ArgumentParser(description="model benchmark data")

    parser.add_argument("path", help="path to model")

    parser.add_argument(
        "--repeat",
        help="how many times to repeat each model",
        type=int,
        default=6,
    )

    parser.add_argument("--output", "-o", help="path for result file")

    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()

    serialize_args = serialize.build_parser().parse_args(
        [args.path, "--use_shards"]
    )

    results = dict()
    results["model"] = args.path
    results["ram"] = psutil.virtual_memory().total

    times = list()
    for _ in range(args.repeat):
        st = time.time()
        payload = serialize.run(serialize_args)
        en = time.time()
        times.append(en - st)

    results["times"] = times
    results["cpu"] = cpuinfo.get_cpu_info()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=4)
    else:
        json.dump(results, sys.stdout, ensure_ascii=False, indent=4)
