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


"""Script for running a benchmark to pick a shard parameter."""

import argparse
import time
from typing import Final

from google.protobuf import json_format
import serialize

from model_signing.signing import in_toto


KB: Final[int] = 1000
MB: Final[int] = 1000 * KB
GB: Final[int] = 1000 * MB


def build_parser() -> argparse.ArgumentParser:
    """Builds the command line parser for the shard experiment."""
    parser = argparse.ArgumentParser(
        description="shard size benchmark data for model signing"
    )

    parser.add_argument("path", help="path to model")

    parser.add_argument(
        "--repeat",
        help="how many times to repeat each shard size",
        type=int,
        default=5,
    )

    parser.add_argument(
        "--sizes", help="shard sizes to benchmark", nargs="+", type=int
    )

    return parser


def _default_sizes() -> list[int]:
    sizes = []
    for scale in [MB, GB]:
        for d in [1, 2, 5, 10, 20, 50, 100, 200, 500]:
            if d * scale > 10 * GB:
                break
            sizes.append(d * scale)
    return sizes


if __name__ == "__main__":
    shard_args = build_parser().parse_args()

    shard_sizes = shard_args.sizes or _default_sizes()
    padding = len(f"{max(shard_sizes)}: ")
    for shard in shard_sizes:
        times = []
        manifest_size = None
        for _ in range(shard_args.repeat):
            args = serialize.build_parser().parse_args(
                [shard_args.path, "--use_shards", f"--shard={shard}"]
            )
            st = time.time()
            payload = serialize.run(args)
            en = time.time()
            times.append(en - st)

            if not isinstance(payload, in_toto.IntotoPayload):
                raise TypeError("IntotoPayloads expected")

            if not manifest_size:
                statement = json_format.MessageToJson(
                    payload.statement.pb
                ).encode("utf-8")
                manifest_size = len(statement)

        print(f"{f'{shard}: ':<{padding}}{min(times):10.4f} {manifest_size:8}")
