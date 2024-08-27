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

"""Signing payload that is just a bytes view on the digest.

In general, this should only be used if we want to sign a model where we have
the hash computed from somewhere else and want to avoid the in-toto types.
"""

import sys

from typing_extensions import override

from model_signing.manifest import manifest as manifest_module
from model_signing.signing import signing


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


class BytesPayload(signing.SigningPayload):
    """A payload that is a view into the bytes of a digest."""

    def __init__(self, digest: bytes):
        """Builds an instance of this payload.

        Don't call this directly in production. Use `from_manifest()` instead.

        Args:
            digest: The digest bytes as extracted from the manifest.
        """
        self.digest = digest

    @classmethod
    @override
    def from_manifest(cls, manifest: manifest_module.Manifest) -> Self:
        """Converts a manifest to the signing payload used for signing.

        The manifest must be a `DigestManifest` instance.

        Args:
            manifest: the manifest to convert to signing payload.

        Returns:
            An instance of `BytesPayload`.

        Raises:
            TypeError: If the manifest is not `DigestManifest`.
        """
        if not isinstance(manifest, manifest_module.DigestManifest):
            raise TypeError("Only DigestManifest is supported")

        # guaranteed to have exactly one item
        subject = list(manifest.resource_descriptors())[0]
        return cls(subject.digest.digest_value)
