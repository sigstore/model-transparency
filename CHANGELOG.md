# Changelog

All notable changes to `model-signing` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

All versions prior to 1.0.0 are untracked.

## [Unreleased]

## [1.0.1] - 2024-04-18

### Added
- Added support for pre v1.0 signatures used in production. This is only provided for verification and replicates the experimental behavior at v0.2, bug for bug.
- Added support for displaying fingerprints of certificates when using signing certificates

### Fixed
- Fix bug in CLI scripts where even if signature verification failed, the script would also output that verification passed and exit with success error code.
- Docker containers wrapping around the CLI have been changed to support the updated CLI

## [1.0.0] - 2024-04-04

### Added
- First stable release of `model_signing`.
- Stable, backwards-compatible API.
- Stable, clean, backwards-compatible CLI wrapping the API.
- Well-defined signature scheme based on Sigstore bundle and DSSE envelope.
- Well-defined, future proof, stable, in-toto format for the model signature.
- Signing and verification using Sigstore, public/private key pairs, and signing certificates.
- Support for signing/verification via scripts in the repo (`hatch run python -m model_signing`), installing the pip package (`python -m model_signing` or `model_signing`), or Docker containers that wrap around the CLI.
- Support for Python 3.9, 3.10, 3.11, 3.12, and 3.13.
- [Demo notebook](https://colab.sandbox.google.com/drive/18IB_uipduXYq0ohMxJv2xHfeihLIcGMT) to showcase API and CLI examples.


[Unreleased]: https://github.com/sigstore/model-transparency/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/sigstore/model-transparency/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/sigstore/model-transparency/compare/v0.1.0...v1.0.0
