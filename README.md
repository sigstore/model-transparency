# Model Transparency

<img align="right" src="https://slsa.dev/images/logo-mono.svg" width="140" height="140">

<!-- markdown-toc --bullets="-" -i README.md -->

<!-- toc -->

- [Overview](#overview)
- [Projects](#projects)
  - [Model Signing](#model-signing)
  - [SLSA for ML](#slsa-for-ml)
- [Status](#status)
- [Contributing](#contributing)

<!-- tocstop -->

## Overview

There is currently significant growth in the number of ML-powered applications.
This brings benefits, but it also provides grounds for attackers to exploit
unsuspecting ML users. This is why Google launched the [Secure AI Framework
(SAIF)][saif] to establish industry standards for creating trustworthy and
responsible AI applications. The first principle of SAIF is to

> Expand strong security foundations to the AI ecosystem

Building on the work with [Open Source Security Foundation][openssf], we are
creating this repository to demonstrate how the ML supply chain can be
strengthened in _the same way_ as the traditional software supply chain.

This repository hosts a collection of utilities and examples related to the
security of machine learning pipelines. The focus is on providing *verifiable*
claims about the integrity and provenance of the resulting models, meaning users
can check for themselves that these claims are true rather than having to just
trust the model trainer.

## Projects

Currently, there are two main projects in the repository: model signing (to
prevent tampering of models after publication to ML model hubs) and
[SLSA](https://slsa.dev/) (to prevent tampering of models during the build
process).

### Model Signing

This project demonstrates how to protect the integrity of a model by signing it
with [Sigstore](https://www.sigstore.dev/), a tool for making code signatures
transparent without requiring management of cryptographic key material.

When users download a given version of a signed model they can check that the
signature comes from a known or trusted identity and thus that the model hasn't
been tampered with after training.

We are able to sign large models with very good performance, as the following
table shows:

| Model              | Size  |  Sign Time | Verify Time |
|--------------------|-------|:----------:|:-----------:|
| roberta-base-11    | 8K    | 1s         | 0.6s        |
| hustvl/YOLOP       | 215M  | 1s         | 1s          |
| bertseq2seq        | 2.8G  | 1.9s       | 1.4s        |
| bert-base-uncased  | 3.3G  | 1.6s       | 1.1s        |
| tiiuae/falcon-7b   | 14GB  | 2.1s       | 1.8s        |

See [README.model_signing.md](README.model_signing.md) for more information.

### SLSA for ML

This project shows how we can generate [SLSA][slsa] provenance for ML models,
using either Github Actions or Google Cloud Platform.

SLSA was originally developed for traditional software to protect against
tampering with builds, such as in the [Solarwinds attack][solarwinds], and
this project is a proof of concept that the same supply chain protections
can be applied to ML.

We support both TensorFlow and PyTorch models. The examples train a model
on [CIFAR10][cifar10] dataset, save it in one of the supported formats, and
generate provenance for the output. The supported formats are:

| Workflow Argument            | Training Framework | Model format                    |
|------------------------------|--------------------|---------------------------------|
| `tensorflow_model.keras`     | TensorFlow         | Keras format (default)          |
| `tensorflow_hdf5_model.h5`   | TensorFlow         | Legacy HDF5 format              |
| `tensorflow_hdf5.weights.h5` | TensorFlow         | Legacy HDF5 weights only format |
| `pytorch_model.pth`          | PyTorch            | PyTorch default format          |
| `pytorch_full_model.pth`     | PyTorch            | PyTorch complete model format   |
| `pytorch_jitted_model.pt`    | PyTorch            | PyTorch TorchScript format      |

See [slsa_for_models/README.md](slsa_for_models/README.md) for more information.

## Status

This project is currently experimental, not ready for all production use-cases.
We may make breaking changes until the first official release.

## Contributing

Please see the [Contributor Guide](CONTRIBUTING.md) for more information.

[slsa]: https://slsa.dev/
[saif]: https://blog.google/technology/safety-security/introducing-googles-secure-ai-framework/
[openssf]: https://openssf.org/
[slsa-generator]: https://github.com/slsa-framework/slsa-github-generator
[solarwinds]: https://www.techtarget.com/whatis/feature/SolarWinds-hack-explained-Everything-you-need-to-know
