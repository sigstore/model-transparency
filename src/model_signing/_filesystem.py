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

_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
    | {f"COM{i}" for i in "¹²³"}
    | {f"LPT{i}" for i in "¹²³"}
)


def as_path(path: PathLike) -> Path:
    """Builds a local pathlib path or a URI-aware epath path."""
    if isinstance(path, pathlib.Path):
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
    if is_remote(path):
        return False
    return pathlib.Path(os.fspath(path)).is_symlink()


def relative_path_parts(
    path: str | os.PathLike, *, windows_compatible: bool = False
) -> tuple[str, ...]:
    """Returns safe POSIX components for a model-relative path.

    Manifest identifiers are POSIX paths. Parent traversal and absolute paths
    are invalid everywhere. When joining to a local Windows root, additionally
    reject names that Windows interprets as separators, drives, alternate data
    streams, aliases, or devices.
    """
    raw_path = os.fspath(path)
    if isinstance(raw_path, bytes):
        raw_path = os.fsdecode(raw_path)
    pure_path = pathlib.PurePosixPath(raw_path)
    if pure_path.is_absolute() or ".." in pure_path.parts:
        raise ValueError(f"Path must be relative to the model root: {raw_path}")
    if windows_compatible:
        for part in pure_path.parts:
            stem = part.split(".", maxsplit=1)[0].rstrip(" .").upper()
            if (
                "\\" in part
                or ":" in part
                or part.endswith((".", " "))
                or stem in _WINDOWS_RESERVED_NAMES
            ):
                raise ValueError(
                    f"Path is not a safe Windows model path: {raw_path}"
                )
    return pure_path.parts


def join_relative_path(model_root: Path, path: str | os.PathLike) -> Path:
    """Joins a validated model-relative POSIX path to its model root."""
    parts = relative_path_parts(
        path,
        windows_compatible=isinstance(model_root, pathlib.Path)
        and os.name == "nt",
    )
    return model_root.joinpath(*parts)


def check_path_within_model(
    model_root: Path, path: Path, *, allow_symlinks: bool
) -> None:
    """Validates containment and the symlink policy for a selected path."""
    try:
        relative_path = path.relative_to(model_root)
    except ValueError as exc:
        raise ValueError(
            f"Path '{path}' is outside model '{model_root}'"
        ) from exc

    if is_remote(model_root) or allow_symlinks:
        return

    local_root = pathlib.Path(os.fspath(model_root))
    current = local_root
    if current.is_symlink():
        raise ValueError(f"Cannot use '{current}' because it is a symlink.")
    for part in relative_path.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"Cannot use '{current}' because it is a symlink.")

    try:
        pathlib.Path(os.fspath(path)).resolve().relative_to(
            local_root.resolve()
        )
    except ValueError as exc:
        raise ValueError(
            f"Path '{path}' resolves outside model '{model_root}'"
        ) from exc


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
    seen = {os.fspath(model_path)}
    while directories:
        directory = directories.pop()
        for child in directory.iterdir():
            child_key = os.fspath(child)
            if child_key in seen:
                continue
            child_is_directory = child.is_dir()
            child_is_file = child.is_file()
            # Some object-store listings expose an explicit `foo/` marker as
            # the synthetic, nonexistent child `foo/foo`. Do not recurse into
            # or serialize that adapter artifact.
            if (
                child.name == directory.name
                and not child_is_directory
                and not child_is_file
            ):
                continue
            seen.add(child_key)
            yield child
            if child_is_directory:
                directories.append(child)
