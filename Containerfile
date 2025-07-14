# Copyright 2025 The Sigstore Authors
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

# Default
ARG BUILD_TYPE=minimal

FROM python:3.13-slim AS base_builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    g++ \
    swig

FROM base_builder AS minimal_install
WORKDIR /app
COPY . /app
RUN pip install .

FROM base_builder AS full_install
WORKDIR /app
COPY . /app
RUN pip install .[pkcs11,otel]

FROM python:3.13-slim AS minimal_image
COPY --from=minimal_install /usr/local/bin /usr/local/bin
COPY --from=minimal_install /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages

FROM python:3.13-slim AS full_image
COPY --from=full_install /usr/local/bin /usr/local/bin
COPY --from=full_install /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages

FROM ${BUILD_TYPE}_image AS final_image

ENTRYPOINT ["model_signing"]
CMD ["--help"]

ARG APP_VERSION="1.0.1"

LABEL org.opencontainers.image.title="Model Transparency Library" \
      org.opencontainers.image.description="Supply chain security for ML" \
      org.opencontainers.image.version="$APP_VERSION" \
      org.opencontainers.image.authors="The Sigstore Authors <sigstore-dev@googlegroups.com>" \
      org.opencontainers.image.licenses="Apache-2.0" \
