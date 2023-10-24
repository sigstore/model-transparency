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

There is a significant growth in the number of ML-powered applications. However,
this also provides grounds for attackers to exploit unsuspecting ML users. This
is why Google launched [Secure AI Framework (SAIF)][saif] to help chart a path
towards creating trustworhty AI applications. The first principle of SAIF is

> Expand strong security foundations to the AI ecosystem

Building on the work with [Open Source security Foundation][openssf] we are
creating this repository to prove how the ML supply chain can be strengthen in
_the same way_ as the traditional software supply chain.

This repository hosts a collection of utilities and examples related to the
security of machine learning pipelines. The focus is on providing *verifiable*
claims about the integrity and provenance of the resulting models, meaning users
can check for themselves that these claims are true rather than having to just
trust the model trainer.

## Projects

Currently, there are 2 main projects in the repository: model signing (to
prevent tampering of models after publication to ML model hubs) and
[SLSA](https://slsa.dev/) (to prevent tampering of models during the build
process).

### Model Signing

This project demonstrates how to protect the integrity of a model by signing it
with [Sigstore](https://www.sigstore.dev/), a tool for making code signatures
transparent without requiring key maintenance.

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

See [model_signing/README.md](model_signing/README.md) for more information.

### SLSA for ML

To protect the supply chain of traditional software against tampering (like in
the [Solarwinds attack][solarwinds]), we can generate SLSA provenance, for
example by using the [SLSA L3 GitHub generator][slsa-generator].

This projects shows how we can use the same generator for training models via
GitHub Actions. While most of the ML models are too expensive to train in such a
fashion, this is a proof of concept to prove that _the same traditional software
supply chain protections can be applied to ML_. Future work will involve
covering training ML models that require access to accelerators (i.e., GPUs,
TPUs) or that require multiple hours for training.

See [slsa_for_models/README.md](slsa_for_models/README.md) for more information.

## Status

This project is currently in alpha. We may make breaking changes until the first
official release. All code should be viewed as experimental and should not be
used in any production environment.

## Contributing

Please see the [Contributor Guide](CONTRIBUTING.md) for more information.

[saif]: https://blog.google/technology/safety-security/introducing-googles-secure-ai-framework/
[openssf]: https://openssf.org/
[slsa-generator]: https://github.com/slsa-framework/slsa-github-generator
[solarwinds]: https://www.techtarget.com/whatis/feature/SolarWinds-hack-explained-Everything-you-need-to-know
