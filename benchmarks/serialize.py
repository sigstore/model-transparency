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

"""Script for benchmarking full model serialization."""

import argparse
from collections.abc import Callable
import pathlib

from model_signing._hashing import hashing
from model_signing._hashing import io
from model_signing._hashing import memory
from model_signing._serialization import file
from model_signing._serialization import file_shard
from model_signing._signing import signing


def get_hash_engine_factory(
    hash_algorithm: str,
) -> type[hashing.StreamingHashEngine]:
    """Returns the class that implements a hashing method.

    Args:
        hash_algorithm: the hash algorithm to implement.

    Returns:
        The class that corresponds to the algorithm.

    Raises:
        ValueError: if the algorithm is not implemented/not valid.
    """
    match hash_algorithm:
        case "sha256":
            return memory.SHA256
        case "blake2":
            return memory.BLAKE2
        case "blake3":
            return memory.BLAKE3
        case _:
            raise ValueError(
                f"Cannot convert {hash_algorithm} to a hash engine"
            )


def get_sharded_file_hasher_factory(
    hash_algorithm: str, chunk_size: int, shard_size: int
) -> Callable[[pathlib.Path, int, int], io.ShardedFileHasher]:
    """Returns a hasher factory for sharded serialization.

    Args:
        hash_algorithm: the hash algorithm to use for each shard.
        chunk_size: the chunk size to use when reading shards.
        shard_size: the shard size used in generating the shards.

    Returns:
        A callable for the hashing factory.
    """
    hash_engine = get_hash_engine_factory(hash_algorithm)

    def _hasher_factory(
        path: pathlib.Path, start: int, end: int
    ) -> io.ShardedFileHasher:
        return io.ShardedFileHasher(
            path,
            hash_engine(),  # pytype: disable=not-instantiable
            start=start,
            end=end,
            chunk_size=chunk_size,
            shard_size=shard_size,
        )

    return _hasher_factory


def get_file_hasher_factory(
    hash_algorithm: str, chunk_size: int
) -> Callable[[pathlib.Path], io.FileHasher]:
    """Returns a hasher factory for file serialization.

    Args:
        hash_algorithm: the hash algorithm to use for each file.
        chunk_size: the chunk size to use when reading files.

    Returns:
        A callable for the hashing factory.
    """
    hash_engine = get_hash_engine_factory(hash_algorithm)

    def _hasher_factory(path: pathlib.Path) -> io.FileHasher:
        return io.SimpleFileHasher(
            path,
            hash_engine(),  # pytype: disable=not-instantiable
            chunk_size=chunk_size,
        )

    return _hasher_factory


def run(args: argparse.Namespace) -> signing.Payload | None:
    """Performs the benchmark.

    Args:
        args: The arguments specifying the benchmark scenario.
    """
    # 1. Hashing layer
    if args.use_shards:
        hasher = get_sharded_file_hasher_factory(
            args.hash_method, args.chunk, args.shard
        )
    else:
        hasher = get_file_hasher_factory(args.hash_method, args.chunk)

    # 2. Serialization layer
    if args.use_shards:
        serializer_factory = file_shard.Serializer
    else:
        serializer_factory = file.Serializer

    serializer = serializer_factory(hasher, max_workers=args.max_workers)

    # Put everything together
    if not args.dry_run:
        manifest = serializer.serialize(args.path)
        if not args.skip_manifest:
            return signing.Payload(manifest)


def build_parser() -> argparse.ArgumentParser:
    """Builds the command line parser for the bechmark runner."""
    parser = argparse.ArgumentParser(
        description="Benchmark full serialization of a model for model signing"
    )

    parser.add_argument("path", help="path to model", type=pathlib.Path)
    parser.add_argument(
        "--dry_run", help="don't run anything", action="store_true"
    )
    parser.add_argument(
        "--hash_method",
        help="hash method to use (default: sha256)",
        choices=["sha256", "blake2", "blake3"],
        default="sha256",
    )
    parser.add_argument(
        "--max_workers", help="number of parallel workers to use", type=int
    )

    param_groups = parser.add_argument_group("Internal parameters to fine-tune")
    param_groups.add_argument(
        "--chunk",
        help="chunk size (default: 1048576)",
        type=int,
        default=1048576,
    )
    param_groups.add_argument(
        "--shard",
        help="shard size (default: 1000000000)",
        type=int,
        default=1_000_000_000,
    )

    shard_group = parser.add_argument_group("Serialization modes")
    shard_group.add_argument(
        "--use_shards", help="serialize by shards", action="store_true"
    )
    shard_group.add_argument(
        "--skip_manifest",
        help="serialize to a single digest, skip manifest creation",
        action="store_true",
    )
    shard_group.add_argument(
        "--merge_hasher",
        help="hasher to use to merge individual hashes "
        "when skipping manifest creation (default: sha256)",
        choices=["sha256", "blake2", "blake3"],
        default="sha256",
    )

    intoto_group = parser.add_argument_group(
        "Manifest to in-toto serialization formats"
    )
    intoto_group.add_argument(
        "--single_digest",
        help="serialize to a single digest, use manifest with one entry",
        action="store_true",
    )
    intoto_group.add_argument(
        "--digest_of_digests",
        help="generate an in-toto statement with a single subject",
        action="store_true",
    )

    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    if args.skip_manifest and (args.single_digest or args.digest_of_digests):
        raise ValueError(
            "Cannot combine --skip_manifest with manifest to in-toto options"
        )
    if args.single_digest and args.digest_of_digests:
        raise ValueError(
            "At most one of --single_digest and --digest_of_digests can be used"
        )
    run(args)
