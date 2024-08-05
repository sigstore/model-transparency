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

"""Sigstore based signature, signers and verifiers."""

import pathlib
from typing import Self

from sigstore import models as sigstore_models
from typing_extensions import override

from model_signing.signing import signing


class SigstoreSignature(signing.Signature):
    """Sigstore signature support, wrapping around `sigstore_models.Bundle`."""

    def __init__(self, bundle: sigstore_models.Bundle):
        """Builds an instance of this signature.

        Args:
            bundle: the Sigstore `Bundle` to wrap around.
        """
        self.bundle = bundle

    @override
    def write(self, path: pathlib.Path) -> None:
        """Writes the signature to disk, to the given path.

        The Sigstore `Bundle` is written in JSON format, per the
        canonicalization defined by the `sigstore-python` library.

        Args:
            path: the path to write the signature to.
        """
        path.write_text(self.bundle.to_json())

    @classmethod
    @override
    def read(cls, path: pathlib.Path) -> Self:
        """Reads the signature from disk.

        Does not perform any signature verification, except what is needed to
        parse the signature file.

        Args:
            path: the path to read the signature from.

        Returns:
            A `SigstoreSignature` object wrapping a Sigstore `Bundle`.

        Raises:
            ValueError: If the Sigstore `Bundle` could not be deserialized from
              the contents of the file pointed to by `path`.
        """
        content = path.read_text()
        return cls(sigstore_models.Bundle.from_json(content))
