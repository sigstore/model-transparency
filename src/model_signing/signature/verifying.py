# Copyright (c) 2024, NVIDIA CORPORATION.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""This package provides the functionality to verify signed models."""

import abc

from sigstore_protobuf_specs.dev.sigstore.bundle import v1 as bundle_pb


class VerificationError(Exception):
    """Typed verification error to provide error handling information."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


class Verifier(abc.ABC):
    """Verifier is the abstract base class for all verifying methods."""

    @abc.abstractmethod
    def verify(self, bundle: bundle_pb.Bundle) -> None:
        """Verify the signature of the provided bundle.

        Args:
            bundle (bundle_pb.Bundle): the bundle that needs to be verified.

        Raises:
            VerificationError: verification failure exception.
        """
