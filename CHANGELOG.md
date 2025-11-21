# Changelog

All notable changes to `model-signing` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

All versions prior to 1.0.0 are untracked.

## [Unreleased]

### Added
- Added support for signing and verifying OCI model manifests directly without requiring model files on disk. Now, we can detect OCI manifest JSON files and sign from them or verify against them. When verifying local files against signatures created from OCI manifests, the tool automatically matches files by path using `org.opencontainers.image.title` annotations (ORAS-style), enabling cross-verification between OCI images and local model directories.

### Changed
- ...

### Fixed
- Fixed a bug where ignored symlinks could raise `ValueError`s if allow_symlinks was unset, even though they were skipped during serialization. ([#550](https://github.com/sigstore/model-transparency/pull/550))
- Fixed a bug where any PEM encoded key could be read during the key-based flows which resulted in a Python exception because the rest of the code only supported elliptic curve keys. ([#573](https://github.com/sigstore/model-transparency/pull/573))

### Removed
- Removed Python 3.9 support due to it reaching EOL 2025-10-31 (https://devguide.python.org/versions/)

## [1.1.1] - 2025-10-10

### Fixed
- Fixed a bug where the API with default signing configuration results in an error due to a type confusion ([#545](https://github.com/sigstore/model-transparency/pull/545))

## [1.1.0] - 2025-10-10

### Added
- Added support for signing with PKCS #11 devices ([#411](https://github.com/sigstore/model-transparency/pull/411)), as an optional dependency ([#494](https://github.com/sigstore/model-transparency/pull/494)).
- Added support for signing and verifying using private Sigstore instances via the `--trust_config` option ([#460](https://github.com/sigstore/model-transparency/pull/460)).
- Added support for the `--oauth_force_oob` option for the signing CLI flow ([#471](https://github.com/sigstore/model-transparency/pull/471)).
- Added support for specifying `--client_id` and `--client_secret` for OIDC authentication with custom OAuth clients ([#475](https://github.com/sigstore/model-transparency/pull/475)).
- Surfaced the `--allow_symlinks` option to the CLI and library API ([#486](https://github.com/sigstore/model-transparency/pull/486)).
- Implemented public key identifier hash matching for bundle verification ([#493](https://github.com/sigstore/model-transparency/pull/493)).
- Added warning for older verification material formats (e.g., raw public key bytes) during verification, recommending re-signing ([#493](https://github.com/sigstore/model-transparency/pull/493)).
- Added more informative signature mismatch errors: The `ValueError` raised during model verification when a signature mismatch occurs now includes detailed information about what caused the signature verification to fail ([#495](https://github.com/sigstore/model-transparency/pull/495)).
- Created a new, minimal container image. This variant excludes optional dependencies (like OTel and PKCS#11) to reduce footprint, focusing solely on core signing and verification mechanisms ([#499](https://github.com/sigstore/model-transparency/pull/499)).
- Added support for `--ignore_unsigned_files` option in CLI to ignore files that are not part of the manifest but are still present in the model directory ([#501](https://github.com/sigstore/model-transparency/pull/501)).
- Added support to trace sign and verify operations using OpenTelemetry ([#503](https://github.com/sigstore/model-transparency/pull/503)).
- The library was migrated to require at least v4.0.0 of `sigstore` due to breaking changes in that library ([#532](https://github.com/sigstore/model-transparency/pull/532)). There are no breaking changes within the library itself, as these changes should be transparent to the users.
- The `sigstore_protobuf_specs` dependency was replaced with `sigstore_models` due to the same changes in `sigstore-4.0.0` ([#533](https://github.com/sigstore/model-transparency/pull/533)). These changes should also be transparent to the users.
- Added support for BLAKE3 hashing ([#538](https://github.com/sigstore/model-transparency/pull/538)).

### Changed
- Adjusted model name when signing and verifying when `model_path` is current directory ([#452](https://github.com/sigstore/model-transparency/pull/452)).
- Recorded files in signature that were ignored when signature was created and added ability to automatically ignore those files when verifying signature ([#462](https://github.com/sigstore/model-transparency/pull/462)).
- The Sigstore signer was changed to be lazily initialized to avoid network calls when not using it ([#467](https://github.com/sigstore/model-transparency/pull/467)).
- Logging was migrated to only be enabled when the user asks to log the certificate fingerprints ([#472](https://github.com/sigstore/model-transparency/pull/472)).

### Fixed
- Fixed bugs related to using `model_path='.'` in the signature, as well as other issues related to file paths ([#452](https://github.com/sigstore/model-transparency/pull/452)).
- Fixed handling of certificate that has no `KeyUsage` ([#457](https://github.com/sigstore/model-transparency/pull/457)).
- Fixed bug related to ignoring git files ([#462](https://github.com/sigstore/model-transparency/pull/462)).
- Fixed handling of ignored files in the sharded file hasher ([#465](https://github.com/sigstore/model-transparency/pull/465)).
- Fixed handling of path resulting from certificates returned from `certify` API ([#468](https://github.com/sigstore/model-transparency/pull/468)).
- Fixed deserialization bug related to optional values in protobuf API for keyid ([#490](https://github.com/sigstore/model-transparency/pull/490)).

## [1.0.1] - 2025-04-18

### Added
- Added support for pre v1.0 signatures used in production. This is only provided for verification and replicates the experimental behavior at v0.2, bug for bug.
- Added support for displaying fingerprints of certificates when using signing certificates

### Fixed
- Fix bug in CLI scripts where even if signature verification failed, the script would also output that verification passed and exit with success error code.
- Docker containers wrapping around the CLI have been changed to support the updated CLI

## [1.0.0] - 2025-04-04

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


[Unreleased]: https://github.com/sigstore/model-transparency/compare/v1.1.1...HEAD
[1.1.1]: https://github.com/sigstore/model-transparency/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/sigstore/model-transparency/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/sigstore/model-transparency/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/sigstore/model-transparency/compare/v0.1.0...v1.0.0
