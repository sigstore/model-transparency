# Model Signing

This project demonstrates how to protect the integrity of a model by signing it with [Sigstore](https://www.sigstore.dev/).

## Installation and usage

### Prerequisites

```shell
sudo apt install git git-lfs python3-venv python3-pip
git lfs install
```

### Installation

```shell
git clone git@github.com:google/model-transparency.git
cd model-transparency/model_signing
python3 -m venv test_env
source test_env/bin/activate
python3 -m pip install --require-hashes -r install/requirements.txt
deactivate
```

## Running the CLI

```shell
python3 main.py -h
```

### Signing and Verifying Models / Training Checkpoints

```shell
# Enter the virtual environment.
source test_env/bin/activate

path=path/to/model

# Signing.
python3 main.py sign -h
# Note: the example stores the signature as `<file>.sig` for a file, and `<dir>/model.sig` for a folder.
python3 main.py sign --path "${path}"

# Verification.
python3 main.py verify -h
python3 main.py verify --path "${path}" \
    --identity-provider https://accounts.google.com \
    --identity myemail@gmail.com

# Leave the venv.
deactivate
```

### Supported Identity Providers

Google's provider is `https://accounts.google.com`.

GitHub's provider is `https://github.com/login/oauth`.

Microsoft's provider is `https://login.microsoftonline.com`.

### Supported Models

#### TensorFlow / Tf Hub

Example for Bertseq2seq model:

```shell
model_path=bertseq2seq
wget "https://tfhub.dev/google/bertseq2seq/bert24_en_de/1?tf-hub-format=compressed" -O "${model_path}".tgz
mkdir -p "${model_path}"
cd "${model_path}" && tar xvzf ../"${model_path}".tgz && rm ../"${model_path}".tgz && cd -
python3 main.py sign --path "${model_path}"
python3 main.py verify --path "${model_path}" \
    --identity-provider https://accounts.google.com \
    --identity myemail@gmail.com
```

#### Hugging face

Pre-requisite: Install large file support for git:

```shell
sudo apt install git-lfs
git lfs install
```

Example for Bert base model:

```shell
model_name=bert-base-uncased
model_path="${model_name}"
git clone --depth=1 "https://huggingface.co/${model_name}" && rm -rf "${model_name}"/.git
python3 main.py sign --path "${model_path}"
python3 main.py verify --path "${model_path}" \
    --identity-provider https://accounts.google.com \
    --identity myemail@gmail.com
```

Example for Falcon model:

```shell
model_name=tiiuae/falcon-7b
model_path=$(echo "${model_name}" | cut -d/ -f2)
git clone --depth=1 "https://huggingface.co/${model_name}" && rm -rf "${model_name}"/.git
python3 main.py sign --path "${model_path}"
python3 main.py verify --path "${model_path}" \
    --identity-provider https://accounts.google.com \
    --identity myemail@gmail.com
```

#### PyTorch Hub

Example for YOLOP model:

Pre-requisite: Install unzip:

```shell
sudo apt install unzip
```

```shell
model_name=hustvl/YOLOP
model_path=$(echo "${model_name}" | cut -d/ -f2)
wget "https://github.com/${model_name}/archive/main.zip" -O "${model_path}".zip
mkdir -p "${model_path}"
cd "${model_path}" && unzip ../"${model_path}".zip && rm ../"${model_path}".zip && shopt -s dotglob && mv YOLOP-main/* . && shopt -u dotglob && rmdir YOLOP-main/ && cd -
python3 main.py sign --path "${model_path}"
python3 main.py verify --path "${model_path}" \
    --identity-provider https://accounts.google.com \
    --identity myemail@gmail.com
```

#### ONNX

Example for Roberta model:

```shell
model_name=roberta-base-11
model_path="${model_name}.onnx"
wget "https://github.com/onnx/models/raw/main/text/machine_comprehension/roberta/model/${model_name}.onnx"
python3 main.py sign --path "${model_path}"
python3 main.py verify --path "${model_path}" \
    --identity-provider https://accounts.google.com \
    --identity myemail@gmail.com
```

## Benchmarking

Install as per [Prerequisites section](#prerequisites)
Ensure you have enough disk space: >= 50GB when passing 3rd script argument as "true", else >= 100GB.

To run the benchmarks:

```bash
git clone git@github.com:google/model-transparency.git
cd model-transparency/model_signing
bash benchmarks/run.sh https://accounts.google.com myemail@gmail.com [true]
```

A single run was performed.

Hashes used:
- H1: Hashing using a tree representation of the directory.
- H2: Hashing using a list representation of the directory. (Implementation is parallized with shards of 1GB sizes across vCPUs).

Machine M1: Debian 6.3.11 x86_64 GNU/Linux, 200GB RAM, 48 vCPUs, 512KB cache, AMD EPYC 7B12:

| Hash | Model              | Size  |  Sign Time | Verify Time | 
|------|--------------------|-------|:------:|:-----:|
| H1 | roberta-base-11      | 8K    | 0.8s  | 0.6s  |
| H1 | hustvl/YOLOP         | 215M  | 1.2s  | 0.8s  |
| H1 | bertseq2seq          | 2.8G  | 4.6s  | 4.4s  |
| H1 | bert-base-uncased    | 3.3G  | 5s    | 4.7s  |
| H1 | tiiuae/falcon-7b     | 14GB  | 12.2s | 11.8s |
| H2 | roberta-base-11      | 8K    | 1s    | 0.6s  |
| H2 | hustvl/YOLOP         | 215M  | 1s    | 1s    |
| H2 | bertseq2seq          | 2.8G  | 1.9s  | 1.4s  |
| H2 | bert-base-uncased    | 3.3G  | 1.6s  | 1.1s  |
| H2 | tiiuae/falcon-7b     | 14GB  | 2.1s  | 1.8s  |

Machine M2: Debian 5.10.1 x86_64 GNU/Linux, 4GB RAM, 2 vCPUs, 56320 KB, Intel(R) Xeon(R) CPU @ 2.20GHz:

| Hash | Model              | Size  |  Sign Time | Verify Time | 
|------|--------------------|-------|:------:|:-----:|
| H1 | roberta-base-11      | 8K    | 1.1s  | 0.7s  |
| H1 | hustvl/YOLOP         | 215M  | 1.9s  | 1.7s  |
| H1 | bertseq2seq          | 2.8G  | 18s   | 23.2s |
| H1 | bert-base-uncased    | 3.3G  | 23.4s | 18.9s |
| H1 | tiiuae/falcon-7b     | 14GB  | 2m4s | 2m2s   |
| H2 | roberta-base-11      | 8K    | 1.1s  | 0.8s  |
| H2 | hustvl/YOLOP         | 215M  | 1.9s  | 1.6s  |
| H2 | bertseq2seq          | 2.8G  | 13.8s | 25.9s |
| H2 | bert-base-uncased    | 3.3G  | 22.7s | 23.3s |
| H2 | tiiuae/falcon-7b     | 14GB  | 2m.1s | 2m3s  |
