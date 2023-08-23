# Model Signing

This project demonstrates how to protect the integrity of a model by signing it with [Sigstore](https://www.sigstore.dev/).

## Installation and usage

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
    --email-provider https://accounts.google.com \
    --email myemail@gmail.com

# Leave the venv.
deactivate
```

### Supported Email Providers

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
    --email-provider https://accounts.google.com \
    --email myemail@gmail.com
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
    --email-provider https://accounts.google.com \
    --email myemail@gmail.com
```

Example for Falcon model:

```shell
# NOTE: 27 GB model (PyTorch).
model_name=tiiuae/falcon-7b
model_path=$(echo "${model_name}" | cut -d/ -f2)
git clone "https://huggingface.co/${model_name}"
python3 main.py sign --path "${model_path}"
python3 main.py verify --path "${model_path}" \
    --email-provider https://accounts.google.com \
    --email myemail@gmail.com
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
    --email-provider https://accounts.google.com \
    --email myemail@gmail.com
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
    --email-provider https://accounts.google.com \
    --email myemail@gmail.com
```
