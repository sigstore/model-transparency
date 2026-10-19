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

"""Machinery for serializing ML models."""

import abc
from collections.abc import Iterable
import errno
import logging
import pathlib

from model_signing import manifest


logger = logging.getLogger(__name__)

_WINDOWS_ERROR_CANT_RESOLVE_FILENAME = 1921


def check_file_or_directory(
    path: pathlib.Path, *, allow_symlinks: bool = False
) -> None:
    """Checks that the given path is either a file or a directory.

    There is no support for sockets, pipes, or any other operating system
    concept abstracted as a file.

    Furthermore, this would raise if the path is a broken symlink, if it doesn't
    exists or if there are permission errors.

    Args:
        path: The path to check.
        allow_symlinks: Controls whether symbolic links are included. If a
          symlink is present but the flag is `False` (default) the
          serialization would raise an error.

    Raises:
        ValueError: The path is neither a file or a directory, or the path
          is a symlink and `allow_symlinks` is false.
    """
    if not allow_symlinks and path.is_symlink():
        raise ValueError(
            f"Cannot use '{path}' because it is a symlink. This"
            " behavior can be changed with `allow_symlinks`."
        )
    if not (path.is_file() or path.is_dir()):
        raise ValueError(
            f"Cannot use '{path}' as file or directory. It could be a"
            " special file, it could be missing, or there might be a"
            " permission issue."
        )


def check_symlink(path: pathlib.Path, model_path: pathlib.Path) -> bool:
    """Warns about symlinks targeting outside the model root or forming cycles.

    OMS v1.0 6.1.1: signer MUST report a warning when a symlink target is
    outside the model root, or when a symlink cycle is detected.

    Args:
        path: The symlink path to check.
        model_path: The root of the model directory.

    Returns:
        True if the symlink is usable, False if it should be skipped (cycle).

    Raises:
        ValueError: The symlink cannot be resolved (broken symlink).
    """
    try:
        target = path.resolve(strict=True)
    except RuntimeError:
        # Python 3.12 and earlier raise RuntimeError on symlink loops.
        logger.warning("Symlink cycle detected: '%s'", path)
        return False
    except OSError as err:
        if err.errno == errno.ELOOP or (
            getattr(err, "winerror", None)
            == _WINDOWS_ERROR_CANT_RESOLVE_FILENAME
        ):
            logger.warning("Symlink cycle detected: '%s'", path)
            return False
        # A link that cannot be resolved is not a cycle. Skipping it would
        # leave it out of the manifest at signing and leave it unreported at
        # verification, so it must fail like any other unusable path.
        raise ValueError(
            f"Cannot use '{path}' because it is a broken symlink."
        ) from err

    model_root = model_path.resolve()
    try:
        target.relative_to(model_root)
    except ValueError:
        logger.warning(
            "Symlink '%s' targets '%s' outside model root '%s'",
            path,
            target,
            model_root,
        )

    return True


def should_ignore(
    path: pathlib.Path, ignore_paths: Iterable[pathlib.Path]
) -> bool:
    """Determines if the provided path should be ignored during serialization.

    Args:
        path: The path to check.
        ignore_paths: The paths to ignore while serializing a model.

    Returns:
        Whether or not the provided path should be ignored.
    """
    return any(path.is_relative_to(ignore_path) for ignore_path in ignore_paths)


class Serializer(metaclass=abc.ABCMeta):
    """Generic ML model format serializer."""

    @abc.abstractmethod
    def serialize(
        self,
        model_path: pathlib.Path,
        *,
        ignore_paths: Iterable[pathlib.Path] = frozenset(),
    ) -> manifest.Manifest:
        """Serializes the model given by the `model_path` argument.

        Args:
            model_path: The path to the model.
            ignore_paths: The paths to ignore during serialization. If a
              provided path is a directory, all children of the directory are
              ignored.

        Returns:
            The model's serialized manifest.
        """
