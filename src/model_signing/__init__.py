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

"""Universal model signing library.

The stable high-level API is split into 3 modules:

- model_signing.hashing
- model_signing.signing
- model_signing.verifying
"""

from model_signing import hashing
from model_signing import signing
from model_signing import verifying


__version__ = "0.3.0"


__all__ = ["hashing", "signing", "verifying"]
