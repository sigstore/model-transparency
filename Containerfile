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

"""For the stable high-level API, see model_signing.api."""

__version__ = "0.1.1"

FROM python:3.13-slim

COPY pyproject.toml ./
COPY src ./src

RUN python -m pip install model_signing

RUN echo '#!/bin/bash\n\
cd "/src" && python sign.py "$@"' > /usr/local/bin/sign

RUN echo '#!/bin/bash\n\
cd "/src" && python verify.py "$@"' > /usr/local/bin/verify

RUN echo '#!/bin/bash\n\
echo "Usage:"\n\
echo "  verify  - Runs the verify.py Python script"\n\
echo "  sign    - Runs the sign.py Python script"\n\
echo "  help    - Displays this help message"' > /usr/local/bin/help

RUN chmod +x /usr/local/bin/sign /usr/local/bin/verify /usr/local/bin/help

CMD ["help"]

