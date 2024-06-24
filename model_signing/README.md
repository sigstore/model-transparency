# Model Signing

This project demonstrates how to protect the integrity of a model by signing it
with [Sigstore](https://www.sigstore.dev/), a tool for making code signatures
transparent without requiring management of cryptographic key material.

When users download a given version of a signed model they can check that the
signature comes from a known or trusted identity and thus that the model hasn't
been tampered with after training.

Signing events are recorded to Sigstore's append-only transparency log.
Transparency logs make signing events discoverable: Model verifiers can validate
that the models they are looking at exist in the transparency log by checking a
proof of inclusion (which is handled by the model signing library).
Furthermore, model signers that monitor the log can check for any unexpected
signing events.

Model signers should monitor for occurences of their signing identity in the
log. Sigstore is actively developing a [log
monitor](https://github.com/sigstore/rekor-monitor) that runs on GitHub Actions.

![Signing models with Sigstore](images/sigstore-model-diagram.png)

## Usage

You will need to install a few prerequisites to be able to run all of the
examples below:

```bash
sudo apt install git git-lfs python3-venv python3-pip unzip
git lfs install
```

After this, you can clone the repository, create a Python virtual environment
and install the dependencies needed by the project:

```bash
git clone git@github.com:sigstore/model-transparency.git
cd model-transparency/model_signing
python3 -m venv test_env
source test_env/bin/activate
os=Linux # Supported: Linux, Windows, Darwin.
python3 -m pip install --require-hashes -r "install/requirements_${os}".txt
```

After this point, you can use the project to sign and verify models and
checkpoints. A help message with all arguments can be obtained by passing `-h`
argument, either to the main driver or to the two subcommands:

```bash
python3 main.py -h
python3 main.py sign -h
python3 main.py verify -h
```

Signing a model requires passing an argument for the path to the model. This can
be a path to a file or a directory (for large models, or model formats such as
`SavedModel` which are stored as a directory of related files):

```bash
path=path/to/model
python3 main.py sign --path "${path}"
```

The sign process will start an OIDC workflow to generate a short lived
certificate based on an identity provider. This will be relevant when verifying
the signature, as shown below.

**Note**: The signature is stored as `<file>.sig` for a model serialized as a
single file, and `<dir>/model.sig` for a model in a folder-based format.

For verification, we need to pass both the path to the model and identity
related arguments:

```bash
python3 main.py verify --path "${path}" \
    --identity-provider https://accounts.google.com \
    --identity myemail@gmail.com
```

For developers signing models, there are three identity providers that can
be used at the moment:

* Google's provider is `https://accounts.google.com`.
* GitHub's provider is `https://github.com/login/oauth`.
* Microsoft's provider is `https://login.microsoftonline.com`.

For automated signing using a workload identity, the following platforms
are currently supported, shown with their expected identities:

* GitHub Actions
  (`https://github.com/octo-org/octo-automation/.github/workflows/oidc.yml@refs/heads/main`)
* GitLab CI
  (`https://gitlab.com/my-group/my-project//path/to/.gitlab-ci.yml@refs/heads/main`)
* Google Cloud Platform (`SERVICE_ACCOUNT_NAME@PROJECT_ID.iam.gserviceaccount.com`)
* Buildkite CI (`https://buildkite.com/ORGANIZATION_SLUG/PIPELINE_SLUG`)

### Supported Models

The library supports multiple models, from multiple training frameworks and
model hubs.

For example, to sign and verify a Bertseq2seq model, trained with TensorFlow,
stored in TFHub, run the following commands:

```bash
model_path=bertseq2seq
wget "https://tfhub.dev/google/bertseq2seq/bert24_en_de/1?tf-hub-format=compressed" -O "${model_path}".tgz
mkdir -p "${model_path}"
cd "${model_path}" && tar xvzf ../"${model_path}".tgz && rm ../"${model_path}".tgz && cd -
python3 main.py sign --path "${model_path}"
python3 main.py verify --path "${model_path}" \
    --identity-provider https://accounts.google.com \
    --identity myemail@gmail.com
```

For models stored in Hugging Face we need the large file support from git, which
can be obtained via

```bash
sudo apt install git-lfs
git lfs install
```

After this, we can sign and verify a Bert base model:

```bash
model_name=bert-base-uncased
model_path="${model_name}"
git clone --depth=1 "https://huggingface.co/${model_name}" && rm -rf "${model_name}"/.git
python3 main.py sign --path "${model_path}"
python3 main.py verify --path "${model_path}" \
    --identity-provider https://accounts.google.com \
    --identity myemail@gmail.com
```

Similarly, we can sign and verify a Falcon model:

```bash
model_name=tiiuae/falcon-7b
model_path=$(echo "${model_name}" | cut -d/ -f2)
git clone --depth=1 "https://huggingface.co/${model_name}" && rm -rf "${model_name}"/.git
python3 main.py sign --path "${model_path}"
python3 main.py verify --path "${model_path}" \
    --identity-provider https://accounts.google.com \
    --identity myemail@gmail.com
```

We can also support models from  the PyTorch Hub:

```bash
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

We also support ONNX models, for example Roberta:

```bash
model_name=roberta-base-11
model_path="${model_name}.onnx"
wget "https://github.com/onnx/models/raw/main/text/machine_comprehension/roberta/model/${model_name}.onnx"
python3 main.py sign --path "${model_path}"
python3 main.py verify --path "${model_path}" \
    --identity-provider https://accounts.google.com \
    --identity myemail@gmail.com
```

## Benchmarking

Install as per [Usage section](#usage).
Ensure you have enough disk space:
- if passing 3rd script argument as `true`: at least 50GB
- otherwise: at least 100GB

To run the benchmarks:

```bash
git clone git@github.com:sigstore/model-transparency.git
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

## Development steps

### Linting

`model_signing` is automatically linted and formatted with a collection of tools:

* [flake8](https://github.com/PyCQA/flake8)
* [pytype](https://github.com/google/pytype)

You can run the type checker locally by installing the `dev` dependencies:
```shell
python3 -m venv dev_env
source dev_env/bin/activate
os=Linux # Supported: Linux, Darwin.
python3 -m pip install --require-hashes -r "install/requirements_dev_${os}".txt
```

Then point pytype at the desired module or package:
```shell
pytype --keep-going model_signing/hashing
```
