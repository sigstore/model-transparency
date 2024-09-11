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

from model_signing.hashing import file
from model_signing.hashing import hashing
from model_signing.hashing import memory
from model_signing.serialization import serialize_by_file
from model_signing.serialization import serialize_by_file_shard
from model_signing.signing import in_toto


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

    raise ValueError(f"Cannot convert {hash_algorithm} to a hash engine")


def get_sharded_file_hasher_factory(
    hash_algorithm: str, chunk_size: int, shard_size: int
) -> Callable[[pathlib.Path, int, int], file.ShardedFileHasher]:
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
    ) -> file.ShardedFileHasher:
        return file.ShardedFileHasher(
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
) -> Callable[[pathlib.Path], file.FileHasher]:
    """Returns a hasher factory for file serialization.

    Args:
        hash_algorithm: the hash algorithm to use for each file.
        chunk_size: the chunk size to use when reading files.

    Returns:
        A callable for the hashing factory.
    """
    hash_engine = get_hash_engine_factory(hash_algorithm)

    def _hasher_factory(path: pathlib.Path) -> file.FileHasher:
        return file.SimpleFileHasher(
            path,
            hash_engine(),  # pytype: disable=not-instantiable
            chunk_size=chunk_size,
        )

    return _hasher_factory


def run(args: argparse.Namespace) -> None:
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
    if args.skip_manifest or args.single_digest:
        merge_hasher_factory = get_hash_engine_factory(args.merge_hasher)
        if args.use_shards:
            serializer = serialize_by_file_shard.DigestSerializer(
                hasher,
                merge_hasher_factory(),  # pytype: disable=not-instantiable
                max_workers=args.max_workers,
            )
        else:
            # This gets complicated because the API here is not matching the
            # rest. We should fix this.
            if args.max_workers is not None and args.max_workers != 1:
                raise ValueError("Currently, only 1 worker is supported here")
            serializer = serialize_by_file.DigestSerializer(
                # pytype: disable=wrong-arg-count
                hasher(pathlib.Path("unused")),
                # pytype: enable=wrong-arg-count
                merge_hasher_factory,
            )
    else:
        if args.use_shards:
            serializer_factory = serialize_by_file_shard.ManifestSerializer
        else:
            serializer_factory = serialize_by_file.ManifestSerializer

        serializer = serializer_factory(hasher, max_workers=args.max_workers)

    # 3. Signing layer
    if args.skip_manifest:
        in_toto_builder = id  # Do nothing, just evaluate the argument
    else:
        if args.single_digest:
            in_toto_builder = in_toto.SingleDigestIntotoPayload
        else:
            match (args.digest_of_digests, args.use_shards):
                case (True, True):
                    in_toto_builder = in_toto.DigestOfShardDigestsIntotoPayload
                case (True, False):
                    in_toto_builder = in_toto.DigestOfDigestsIntotoPayload
                case (False, True):
                    in_toto_builder = in_toto.ShardDigestsIntotoPayload
                case (False, False):
                    in_toto_builder = in_toto.DigestsIntotoPayload

        in_toto_builder = in_toto_builder.from_manifest

    # Put everything together
    if not args.dry_run:
        in_toto_builder(serializer.serialize(args.path))


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
        choices=["sha256", "blake2"],
        default="sha256",
    )
    parser.add_argument(
        "--max_workers", help="number of parallel workers to use", type=int
    )

    param_groups = parser.add_argument_group("Internal parameters to fine-tune")
    param_groups.add_argument(
        "--chunk", help="chunk size (default: 8192)", type=int, default=8192
    )
    param_groups.add_argument(
        "--shard",
        help="shard size (default: 1000000)",
        type=int,
        default=1000000,
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
        choices=["sha256", "blake2"],
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
