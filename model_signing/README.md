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
# NOTE: 2.8 GB model.
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
# NOTE: 6.4 GB model (TensorFlow and PyTorch).
model_name=bert-base-uncased
model_path="${model_name}"
git clone "https://huggingface.co/${model_name}"
python3 main.py sign --path "${model_path}"
python3 main.py verify --path "${model_path}" \
    --identity-provider https://accounts.google.com \
    --identity myemail@gmail.com
```

Example for Falcon model:

```shell
# NOTE: 27 GB model (PyTorch).
model_name=tiiuae/falcon-7b
model_path=$(echo "${model_name}" | cut -d/ -f2)
git clone "https://huggingface.co/${model_name}"
python3 main.py sign --path "${model_path}"
python3 main.py verify --path "${model_path}" \
    --identity-provider https://accounts.google.com \
    --identity myemail@gmail.com
```

#### PyTorch Hub

Example for YOLOP model:

```shell
# NOTE: 350M model.
model_name=hustvl/YOLOP
model_path=$(echo "${model_name}" | cut -d/ -f2)
git clone "https://github.com/${model_name}.git"
python3 main.py sign --path "${model_path}"
python3 main.py verify --path "${model_path}" \
    --identity-provider https://accounts.google.com \
    --identity myemail@gmail.com
```

#### ONNX

Example for Roberta model:

```shell
# NOTE: 574M model.
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

Machine M1: Debian 6.3.11 x86_64 GNU/Linux, 100GB RAM, 48 vCPUs, 512KB cache, AMD EPYC 7B12.
Machine M2: Debian 5.10.1 x86_64 GNU/Linux, 4GB RAM, 2 vCPUs, 56320 KB, Intel(R) Xeon(R) CPU @ 2.20GHz.
A single run was performed.

| Machine | Model   |      Size      |  Sign Time | Verify Time | 
|--------|----------|:-------------:|:------:|:------:|
| M1 | roberta-base-11 | 8K | 1s | 0.5s |
| M1 | hustvl/YOLOP | 355M |  1s | 1s |
| M1 | bertseq2seq |    2.8G   |   1.4s |  1.2s |
| M1 | bert-base-uncased |  6.5G | 9.8s | 9.4s |
| M1 | tiiuae/falcon-7b | 27GB | 47s | 46s |
| M2 | roberta-base-11 | 8K | 58.5s | 58.2s |
| M2 | hustvl/YOLOP | 355M | 3.9s | 2.1s |
| M2 | bertseq2seq |    2.8G   |   26.4s |  26.1s |
| M2 | bert-base-uncased |  6.5G | 9.8s | 9.4s |
| M2 | tiiuae/falcon-7b | 27GB | 3m47 | 3m48 |



