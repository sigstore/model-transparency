# Copyright 2024 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""High level API for the verification interface of `model_signing` library.

This module supports configuring the verification method used to verify a model,
before performing the verification.

```python
model_signing.verifying.Config().use_sigstore_verifier(
    identity=identity, oidc_issuer=oidc_provider
).verify("finbert", "finbert.sig")
```

The same verification configuration can be used to verify multiple models:

```python
verifying_config = model_signing.signing.Config().use_elliptic_key_verifier(
    public_key="key.pub"
)

for model in all_models:
    verifying_config.verify(model, f"{model}_sharded.sig")
```

The API defined here is stable and backwards compatible.
"""

from collections.abc import Iterable
import pathlib
import sys

from model_signing import hashing
from model_signing import manifest
from model_signing._hashing import hashing as _hashing
from model_signing._signing import sign_certificate as certificate
from model_signing._signing import sign_ec_key as ec_key
from model_signing._signing import sign_sigstore as sigstore
from model_signing._signing import sign_sigstore_pb as sigstore_pb


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


class Config:
    """Configuration to use when verifying models against signatures.

    The verification configuration is needed to determine how to read and verify
    the signature. Given we support multiple signing format, the verification
    settings must match the signing ones.

    The configuration also supports configuring the hashing configuration from
    `model_signing.hashing`. This should also match the configuration used
    during signing. However, by default, we can attempt to guess it from the
    signature.
    """

    def __init__(self):
        """Initializes the default configuration for verification."""
        self._hashing_config = None
        self._verifier = None
        self._uses_sigstore = False
        self._ignore_unsigned_files = False

    def verify(
        self, model_path: hashing.PathLike, signature_path: hashing.PathLike
    ):
        """Verifies that a model conforms to a signature.

        This method can verify signatures created from either:
        - Local files (normal verification)
        - Model manifests

        Args:
            model_path: The path to the model to verify.
            signature_path: The path to the signature file.

        Raises:
            ValueError: No verifier has been configured.
        """
        if self._verifier is None:
            raise ValueError("Attempting to verify with no configured verifier")

        if self._uses_sigstore:
            signature = sigstore.Signature.read(pathlib.Path(signature_path))
        else:
            signature = sigstore_pb.Signature.read(pathlib.Path(signature_path))

        expected_manifest = self._verifier.verify(signature)

        if self._hashing_config is None:
            self._guess_hashing_config(expected_manifest)
        if "ignore_paths" in expected_manifest.serialization_type:
            self._hashing_config.add_ignored_paths(
                model_path=model_path,
                paths=expected_manifest.serialization_type["ignore_paths"],
            )

        if self._ignore_unsigned_files:
            files_to_hash = [
                model_path / rd.identifier
                for rd in expected_manifest.resource_descriptors()
            ]
        else:
            files_to_hash = None

        actual_manifest = self._hashing_config.hash(
            model_path, files_to_hash=files_to_hash
        )

        if actual_manifest != expected_manifest:
            diff_message = self._get_manifest_diff(
                actual_manifest, expected_manifest
            )
            raise ValueError(f"Signature mismatch: {diff_message}")

    def _verify_oci_layers_from_files(
        self, model_path: hashing.PathLike, expected_manifest: manifest.Manifest
    ):
        """Verify OCI layer-based signature against local files.

        This verifies by matching file paths from the signature with local
        files. If the signature was created from an OCI manifest with file
        path annotations (e.g., org.opencontainers.image.title), it matches
        files by path and compares their digests.

        Args:
            model_path: Path to local model directory
            expected_manifest: Manifest extracted from signature (contains
                layer digests)

        Raises:
            ValueError: If local files don't match the OCI layer digests
        """
        model_path = pathlib.Path(model_path)

        # Check if this is an ORAS-style manifest with file paths in
        # identifiers (not generic layer_*.tar.gz names)
        has_file_paths = False
        expected_file_digests = {}

        for rd in expected_manifest.resource_descriptors():
            identifier = str(rd.identifier)
            if identifier == "config.json":
                continue
            is_generic_layer = identifier.startswith(
                "layer_"
            ) and identifier.endswith(".tar.gz")
            if not is_generic_layer:
                has_file_paths = True
                expected_file_digests[identifier] = rd.digest

        if has_file_paths:
            # ORAS-style: verify by matching individual files by path
            return self._verify_oci_files_by_path(
                model_path, expected_file_digests
            )
        else:
            print(
                "Verification failed: The signature bundle does not contain"
                "file path information."
                "Verification must be performed on an ORAS-style artifact.",
                file=sys.stderr,
            )
            sys.exit(1)

    def _verify_oci_files_by_path(
        self,
        model_path: pathlib.Path,
        expected_file_digests: dict[str, _hashing.Digest],
    ):
        """Verify OCI files by matching paths and computing file digests."""
        import hashlib

        missing_files = []
        mismatched_files = []
        verified_files = []

        for file_path_str, expected_digest in expected_file_digests.items():
            local_file_path = model_path / file_path_str

            if not local_file_path.exists():
                missing_files.append(file_path_str)
                continue

            if not local_file_path.is_file():
                continue

            with open(local_file_path, "rb") as f:
                file_content = f.read()
                file_digest_value = hashlib.sha256(file_content).digest()
                file_digest = _hashing.Digest("sha256", file_digest_value)

            if file_digest == expected_digest:
                verified_files.append(file_path_str)
            else:
                mismatched_files.append(
                    (
                        file_path_str,
                        expected_digest.digest_hex,
                        file_digest.digest_hex,
                    )
                )

        if missing_files or mismatched_files:
            error_parts = []
            if missing_files:
                missing_list = ", ".join(missing_files[:5])
                more_text = (
                    f" ... and {len(missing_files) - 5} more"
                    if len(missing_files) > 5
                    else ""
                )
                error_parts.append(
                    f"Missing files ({len(missing_files)}): "
                    f"{missing_list}{more_text}"
                )
            if mismatched_files:
                mismatches = []
                for path, expected, actual in mismatched_files[:3]:
                    mismatches.append(
                        f"  {path}: expected {expected[:16]}..., "
                        f"got {actual[:16]}..."
                    )
                mismatch_text = "\n".join(mismatches)
                more_mismatches = (
                    f"\n  ... and {len(mismatched_files) - 3} more"
                    if len(mismatched_files) > 3
                    else ""
                )
                error_parts.append(
                    f"Hash mismatches ({len(mismatched_files)}):\n"
                    f"{mismatch_text}{more_mismatches}"
                )

            error_msg = (
                "Verification failed:\n"
                + "\n".join(error_parts)
                + "\n\n"
                + f"Successfully verified {len(verified_files)} file(s)."
            )
            raise ValueError(error_msg)

        return

    def verify_from_oci_manifest(
        self,
        oci_manifest: dict,
        signature_path: hashing.PathLike,
        *,
        include_config: bool = True,
    ):
        """Verifies that an OCI image manifest conforms to a signature.

        This method verifies a signature against an OCI image manifest without
        requiring the actual model files. It extracts the expected manifest from
        the signature and compares it with a manifest created from the OCI image
        manifest.

        Args:
            oci_manifest: The OCI image manifest as a dictionary (from JSON).
              Expected to have "layers" array with "digest" fields,
              and optionally a "config" field with a "digest".
            signature_path: The path to the signature file.
            include_config: Whether to include the config blob digest in the
              comparison. Should match the value used during signing.
              Default is True.

        Raises:
            ValueError: No verifier has been configured,
            the OCI manifest is invalid, or verification
            fails.
        """
        if self._verifier is None:
            raise ValueError("Attempting to verify with no configured verifier")

        if self._uses_sigstore:
            signature = sigstore.Signature.read(pathlib.Path(signature_path))
        else:
            signature = sigstore_pb.Signature.read(pathlib.Path(signature_path))

        expected_manifest = self._verifier.verify(signature)

        actual_manifest = hashing.create_manifest_from_oci_layers(
            oci_manifest, include_config=include_config
        )

        if actual_manifest != expected_manifest:
            diff_message = self._get_manifest_diff(
                actual_manifest, expected_manifest
            )
            raise ValueError(f"Signature mismatch: {diff_message}")

    def _get_manifest_diff(self, actual, expected) -> list[str]:
        diffs = []

        actual_hashes = {
            rd.identifier: rd.digest for rd in actual.resource_descriptors()
        }
        expected_hashes = {
            rd.identifier: rd.digest for rd in expected.resource_descriptors()
        }

        extra_actual_files = set(actual_hashes.keys()) - set(
            expected_hashes.keys()
        )
        if extra_actual_files:
            diffs.append(
                f"Extra files found in model '{actual.model_name}': "
                f"{', '.join(sorted(extra_actual_files))}"
            )

        missing_actual_files = set(expected_hashes.keys()) - set(
            actual_hashes.keys()
        )
        if missing_actual_files:
            diffs.append(
                f"Missing files in model '{actual.model_name}': "
                f"{', '.join(sorted(missing_actual_files))}"
            )

        common_files = set(actual_hashes.keys()) & set(expected_hashes.keys())
        for identifier in sorted(common_files):
            if actual_hashes[identifier] != expected_hashes[identifier]:
                diffs.append(
                    f"Hash mismatch for '{identifier}': "
                    f"Expected '{expected_hashes[identifier]}', "
                    f"Actual '{actual_hashes[identifier]}'"
                )
        return diffs

    def set_hashing_config(self, hashing_config: hashing.Config) -> Self:
        """Sets the new configuration for hashing models.

        After calling this method, the automatic guessing of the hashing
        configuration used during signing is no longer possible from within one
        instance of this class.

        Args:
            hashing_config: The new hashing configuration.

        Returns:
            The new signing configuration.
        """
        self._hashing_config = hashing_config
        return self

    def set_ignore_unsigned_files(self, ignore_unsigned_files: bool) -> Self:
        """Sets whether files that were not signed are to be ignored.

        This method allows to ignore those files that are not part of the
        manifest and therefor were not originally signed.

        Args:
            ignore_unsigned_files: whether to ignore unsigned files
        """
        self._ignore_unsigned_files = ignore_unsigned_files
        return self

    def _guess_hashing_config(self, source_manifest: manifest.Manifest) -> None:
        """Attempts to guess the hashing config from a manifest."""
        args = source_manifest.serialization_type
        method = args["method"]
        match method:
            case "files":
                self._hashing_config = hashing.Config().use_file_serialization(
                    hashing_algorithm=args["hash_type"],
                    allow_symlinks=args["allow_symlinks"],
                    ignore_paths=args.get("ignore_paths", frozenset()),
                )
            case "shards":
                self._hashing_config = hashing.Config().use_shard_serialization(
                    hashing_algorithm=args["hash_type"],
                    shard_size=args["shard_size"],
                    allow_symlinks=args["allow_symlinks"],
                    ignore_paths=args.get("ignore_paths", frozenset()),
                )
            case _:
                raise ValueError("Cannot guess the hashing configuration")

    def use_sigstore_verifier(
        self,
        *,
        identity: str,
        oidc_issuer: str,
        use_staging: bool = False,
        trust_config: pathlib.Path | None = None,
    ) -> Self:
        """Configures the verification of signatures produced by Sigstore.

        The verifier in this configuration is changed to one that performs
        verification of Sigstore signatures (sigstore bundles signed by
        keyless signing via Sigstore).

        Args:
            identity: The expected identity that has signed the model.
            oidc_issuer: The expected OpenID Connect issuer that provided the
              certificate used for the signature.
            use_staging: Use staging configurations, instead of production. This
              is supposed to be set to True only when testing. Default is False.
            trust_config: A path to a custom trust configuration. When provided,
              the signature verification process will rely on the supplied
              PKI and trust configurations, instead of the default Sigstore
              setup. If not specified, the default Sigstore configuration
              is used.

        Return:
            The new verification configuration.
        """
        self._uses_sigstore = True
        self._verifier = sigstore.Verifier(
            identity=identity,
            oidc_issuer=oidc_issuer,
            use_staging=use_staging,
            trust_config=trust_config,
        )
        return self

    def use_elliptic_key_verifier(
        self, *, public_key: hashing.PathLike
    ) -> Self:
        """Configures the verification of signatures generated by a private key.

        The verifier in this configuration is changed to one that performs
        verification of sgistore bundles signed by an elliptic curve private
        key. The public key used in the configuration must match the private key
        used during signing.

        Args:
            public_key: The path to the public key to verify with.

        Return:
            The new verification configuration.
        """
        self._uses_sigstore = False
        self._verifier = ec_key.Verifier(pathlib.Path(public_key))
        return self

    def use_certificate_verifier(
        self,
        *,
        certificate_chain: Iterable[hashing.PathLike] = frozenset(),
        log_fingerprints: bool = False,
    ) -> Self:
        """Configures the verification of signatures generated by a certificate.

        The verifier in this configuration is changed to one that performs
        verification of sgistore bundles signed by a signing certificate.

        Args:
            certificate_chain: Certificate chain to establish root of trust. If
              empty, the operating system's one is used.
            log_fingerprints: Log certificates' SHA256 fingerprints

        Return:
            The new verification configuration.
        """
        self._uses_sigstore = False
        self._verifier = certificate.Verifier(
            [pathlib.Path(c) for c in certificate_chain],
            log_fingerprints=log_fingerprints,
        )
        return self
