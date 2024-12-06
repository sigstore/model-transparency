FROM ubuntu:latest
RUN apt update && apt install -y git git-lfs python3-pip unzip wget
RUN git lfs install

# set env var
ENV MODEL_PATH=/home/bertseq2seq
ENV SIG_PATH=/home/sig
ENV METHOD=private-key
ENV PUB_KEY=/home/public.pem
ENV PRI_KEY=/home/private.pem

# install modified sigstore-python with iat_verify set to false
# otherwise token takes one minute to be validated
WORKDIR /home
RUN openssl ecparam -name prime256v1 -genkey -noout -out private.pem
RUN openssl ec -in private.pem -pubout -out public.pem
# COPY sigstore-python ./sigstore-python
# RUN pip install --break-system-packages ./sigstore-python

COPY model-transparency ./model-transparency
WORKDIR /home/model-transparency
RUN pip install . --break-system-packages

WORKDIR /home/model-transparency/src
CMD "python3 sign.py --model_path "" private-key --private_key ./private.pem"