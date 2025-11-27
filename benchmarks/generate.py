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

"""Script for generating benchmark data."""

import argparse
import itertools
import pathlib

import numpy as np


def create_file_of_given_size(path: str, size: int) -> None:
    """Writes a random file at the given path with given size.

    Args:
        path: Path to a file to write to. Parents are created if needed.
        size: Number of bytes to generate and write to file.
    """
    file_path = pathlib.Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    chunk_size = 1048576
    num_chunks = size // chunk_size

    with file_path.open("wb") as f:
        for _ in range(num_chunks):
            s = np.random.randint(0, 256, chunk_size, dtype=np.uint8).tobytes()
            f.write(s)

        if size % chunk_size != 0:
            chunk_size = size % chunk_size
            s = np.random.randint(0, 256, chunk_size, dtype=np.uint8).tobytes()
            f.write(s)


def generate_file_sizes(
    total_size: int, count: int, weights: list[int] | None = None
) -> list[int]:
    """Generate file sizes splitting a total size into multiple files.

    If weights is missing (or made of equal elements), the resulting files have
    equal sizes. Otherwise, the sizes are proportional to the weights.

    The weights are used in a cycle until all files are accounted for.

    Args:
        total_size: Total size to split into files.
        count: Number of files to generate.
        weights: Optional weights to use when splitting.

    Returns:
        The list of file sizes to generate.
    """
    if weights is None:
        weights = [1]

    weights = list(itertools.islice(itertools.cycle(weights), count))
    total_weight = sum(weights)
    file_sizes = [int(total_size * w / total_weight) for w in weights]
    file_sizes[-1] = total_size - sum(file_sizes[:-1])
    return file_sizes


def generate_file(args: argparse.Namespace):
    """Generates a random model as a single file.

    Args:
        args: The arguments specifying the request.
    """
    create_file_of_given_size(args.root, args.size)


def generate_dir(args: argparse.Namespace):
    """Generates a random model as N files in a directory.

    Args:
        args: The arguments specifying the request.
    """
    for i, sz in enumerate(generate_file_sizes(args.size, args.n, args.w)):
        create_file_of_given_size(f"{args.root}/f{i}", sz)


def generate_matrix(args: argparse.Namespace):
    """Generates a random model as M directories with N files each.

    Args:
        args: The arguments specifying the request.
    """
    sizes = generate_file_sizes(args.size // args.m, args.n, args.w)
    exact = args.size % args.m == 0
    last = args.m if exact else (args.m - 1)

    for i in range(last):
        for j, sz in enumerate(sizes):
            create_file_of_given_size(f"{args.root}/d{i}/f{j}", sz)

    if not exact:
        leftover = (args.size // args.m) + (args.size % args.m)
        i = i + 1
        for j, sz in enumerate(generate_file_sizes(leftover, args.n, args.w)):
            create_file_of_given_size(f"{args.root}/d{i}/f{j}", sz)


def generate_nested(args: argparse.Namespace):
    """Generates a random model as N files in a directory with M ancestors.

    Args:
        args: The arguments specifying the request.
    """
    path = args.root
    for i in range(args.m):
        path = f"{path}/d{i}"

    for j, sz in enumerate(generate_file_sizes(args.size, args.n, args.w)):
        create_file_of_given_size(f"{path}/f{j}", sz)


def add_size_arguments(
    parser: argparse.ArgumentParser, multiple_files: bool = True
) -> None:
    """Adds the size related arguments to a subparser.

    We need to pass in the size of the model to generate. If the model has
    multiple files we support an additional repeated to specify what sizes these
    files should have (instead of being all equal).

    Args:
        parser: The parser to enhance.
        multiple_files: Whether the generator generates multiple files.
    """
    parser.add_argument("size", help="size of the model", type=int)

    if multiple_files:
        parser.add_argument(
            "-w",
            help="optional weights for for model file sizes to generate",
            nargs="+",
            type=int,
        )


def add_count_arguments(
    parser: argparse.ArgumentParser, with_dirs: bool = True
) -> None:
    """Adds the count related arguments to a subparser.

    We have N files. In some cases, we also have M directories.

    Args:
        parser: The parser to enhance.
        with_dirs: Also add argument to generate the directories.
    """
    parser.add_argument("-n", help="number of files", type=int, required=True)

    if with_dirs:
        parser.add_argument(
            "-m", help="number of directories", type=int, required=True
        )


def add_root_argument(parser: argparse.ArgumentParser) -> None:
    """Adds the argument for the name of the root of the model.

    Args:
        parser: The parser to enhance.
    """
    parser.add_argument("--root", help="model root path", required=True)


def build_parser() -> argparse.ArgumentParser:
    """Builds the command line parser for the generator."""
    parser = argparse.ArgumentParser(
        description="generate benchmark data for model signing"
    )
    parser.set_defaults(func=generate_file)
    subparsers = parser.add_subparsers(title="Model shapes")

    parser_file = subparsers.add_parser(
        "file", help="generate all data in a single file (default)"
    )
    add_root_argument(parser_file)
    add_size_arguments(parser_file, multiple_files=False)
    parser_file.set_defaults(func=generate_file)

    parser_dir = subparsers.add_parser(
        "dir", help="generate data split into N files in a single directory"
    )
    add_root_argument(parser_dir)
    add_size_arguments(parser_dir)
    add_count_arguments(parser_dir, with_dirs=False)
    parser_dir.set_defaults(func=generate_dir)

    parser_matrix = subparsers.add_parser(
        "matrix", help="generate data split into N files in M directories"
    )
    add_root_argument(parser_matrix)
    add_size_arguments(parser_matrix)
    add_count_arguments(parser_matrix)
    parser_matrix.set_defaults(func=generate_matrix)

    parser_nested = subparsers.add_parser(
        "nested",
        help="generate data split into N files in a directory nested M levels",
    )
    add_root_argument(parser_nested)
    add_size_arguments(parser_nested)
    add_count_arguments(parser_nested)
    parser_nested.set_defaults(func=generate_nested)

    return parser


if __name__ == "__main__":
    np.random.seed(42)
    args = build_parser().parse_args()
    args.func(args)
