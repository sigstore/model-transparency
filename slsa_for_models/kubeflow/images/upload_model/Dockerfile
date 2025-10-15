FROM gcr.io/google.com/cloudsdktool/cloud-sdk:543.0.0-slim
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install coreutils -y
COPY . /src
WORKDIR /src
RUN chmod +x /src/upload.sh
