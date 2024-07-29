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

"""Machinery for serializing ML models.

Currently we have only one serializer that performs a DFS traversal of the model
directory, but more serializers are coming soon.
"""

import abc
import pathlib

from collections.abc import Iterable

from model_signing.manifest import manifest


class Serializer(metaclass=abc.ABCMeta):
    """Generic ML model format serializer."""

    @abc.abstractmethod
    def serialize(
        self,
        model_path: pathlib.Path,
        ignore_paths: Iterable[pathlib.Path] = frozenset(),
    ) -> manifest.Manifest:
        """Serializes the model given by the `model_path` argument."""
        pass
