FROM gcr.io/google.com/cloudsdktool/cloud-sdk:379.0.0-slim@sha256:d844877c7aaa06a0072979230c68417ddb0f27087277f29747c7169d6ed0d2b9
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install coreutils -y
COPY . /src
WORKDIR /src
RUN chmod +x /src/upload.sh
