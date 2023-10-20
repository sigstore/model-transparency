# Model Transparency

<img align="right" src="https://slsa.dev/images/logo-mono.svg" width="140" height="140">

<!-- markdown-toc --bullets="-" -i README.md -->

<!-- toc -->

- [Overview](#overview)
- [Status](#status)
- [Projects](#projects)
  - [Model Signing](#model-signing)
- [Contributing](#contributing)

<!-- tocstop -->

## Overview

This repository will host a collection of utilities and examples related to the security of machine learning pipelines. The focus is on providing *verifiable* claims about the integrity and provenance of the resulting models, meaning users can check for themselves that these claims are true rather than having to just trust the model trainer.

## Status

This is not an officially supported Google product.

This project is currently in alpha. We may make breaking changes until the first official release. All code should be viewed as experimental and should not be used in any production environment.

## Projects

### Model Signing

This project demonstrates how to protect the integrity of a model by signing it with [Sigstore](https://www.sigstore.dev/), a tool for making code signatures transparent without requiring key maintenance.  When users download a given version of a signed model they can check that the signature comes from a known or trusted identity and thus that the model hasn't been tampered with after training.

See [model_signing/README.md](model_signing/README.md) for more information.

#### Verifying signing events

Signing events are recorded to Sigstore's append-only transparency log. Transparency logs make signing events discoverable, so that model signers
can monitor the logs and determine if any signing events are unexpected. During verification, model verifiers will verify a proof of inclusion from the log,
which is handled by the model signing library.

Model signers should monitor for occurences of their signing identity in the log. Sigstore is actively developing a [log monitor](https://github.com/sigstore/rekor-monitor)
that runs on GitHub Actions.

## Contributing

We are not accepting PRs at this point in time. Please see the [Contributor Guide](CONTRIBUTING.md) for more information. 
