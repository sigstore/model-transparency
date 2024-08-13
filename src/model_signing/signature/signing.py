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
"""This package provides the functionality to sign models."""

import abc

from in_toto_attestation.v1 import statement
from sigstore_protobuf_specs.dev.sigstore.bundle import v1 as bundle_pb


class Signer(abc.ABC):
    """Signer is the abstract base class for all signing methods."""

    @abc.abstractmethod
    def sign(self, stmnt: statement.Statement) -> bundle_pb.Bundle:
        """Sign signs the provide statment.

        Args:
            stmnt (statement.Statement): The statemnt that needs to be signed.

        Returns:
            bundle_pb.Bundle: DSSE envelop and the verification material.
        """
