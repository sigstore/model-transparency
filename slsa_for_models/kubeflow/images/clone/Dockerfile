FROM ubuntu
ARG DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install git-all -y
COPY . /src
WORKDIR /src
RUN chmod +x /src/clone.sh
