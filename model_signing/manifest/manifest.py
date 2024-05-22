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

"""Machinery for representing a serialized representation of an ML model.

Currently, we only support a manifest that wraps around a digest. But, to
support incremental updates and partial signature verification, we need a
manifest that lists files and their digests. That will come in a future change,
soon.
"""

from abc import ABCMeta
from dataclasses import dataclass

from model_signing.hashing import hashing


class Manifest(metaclass=ABCMeta):
    """Generic manifest file to represent a model."""

    pass


@dataclass
class DigestManifest(Manifest):
    """A manifest that is just a hash."""

    digest: hashing.Digest
