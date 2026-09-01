# Copyright 2026 The Sigstore Authors
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

"""Filesystem path helpers shared by model serialization code."""

from collections.abc import Iterator
import os
import pathlib
from typing import TypeAlias

from etils import epath


PathLike: TypeAlias = str | bytes | os.PathLike
Path: TypeAlias = pathlib.Path | epath.Path


def as_path(path: PathLike) -> Path:
    """Builds a local pathlib path or a URI-aware epath path."""
    if isinstance(path, (pathlib.Path, epath.Path)):
        return path

    raw_path = os.fspath(path)
    if isinstance(raw_path, bytes):
        return pathlib.Path(os.fsdecode(raw_path))
    if "://" in raw_path:
        return epath.Path(raw_path)
    return pathlib.Path(raw_path)


def is_remote(path: Path) -> bool:
    """Returns whether a path uses a non-local URI scheme."""
    return not isinstance(path, pathlib.Path) and "://" in os.fspath(path)


def is_symlink(path: Path) -> bool:
    """Checks local symlinks; object-store paths cannot be symlinks."""
    if isinstance(path, pathlib.Path):
        return path.is_symlink()
    return False


def file_size(path: Path) -> int:
    """Returns a file size for pathlib and epath stat result types."""
    result = path.stat()
    if isinstance(result, os.stat_result):
        return result.st_size
    return result.length


def walk_paths(model_path: Path) -> Iterator[Path]:
    """Yields a model and all of its descendants.

    pathlib's existing recursive glob behavior is retained for local paths.
    etils intentionally rejects recursive glob patterns for cloud paths, so
    remote directories are traversed explicitly through their path interface.
    """
    yield model_path
    if isinstance(model_path, pathlib.Path):
        yield from model_path.glob("**/*")
        return

    if not model_path.is_dir():
        return

    directories = [model_path]
    while directories:
        directory = directories.pop()
        for child in directory.iterdir():
            yield child
            if child.is_dir():
                directories.append(child)
