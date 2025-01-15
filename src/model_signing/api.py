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

"""Public, high-level API for the model_signing library.

Users should use this API to sign models and verify the model integrity instead
of reaching out to the internals of the library. We guarantee backwards
compatibility only for the API defined in this file.
"""

from collections.abc import Callable, Iterable
import os
import pathlib
import sys
from typing import Literal, Optional, cast

from model_signing.hashing import file
from model_signing.hashing import hashing
from model_signing.hashing import memory
from model_signing.manifest import manifest
from model_signing.serialization import serialize_by_file
from model_signing.serialization import serialize_by_file_shard
from model_signing.signing import in_toto
from model_signing.signing import sign_sigstore as sigstore
from model_signing.signing import signing


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


def hash(model_path: os.PathLike) -> manifest.Manifest:
    """Hashes a model using the default configuration.

    We use a separate method and configuration for hashing as it needs to be
    common between signing and signature verification. Having thise separate
    also helps with performance testing, as hashing is expected to take the
    largest amount of time (proportional to model size).

    Since we need to be flexible on the serialization format, this returns a
    manifest, instead of just a single digest. The type of returned manifest
    depends on the configuration.

    Args:
        model_path: the path to the model to hash.

    Returns:
        A manifest of the hashed model.
    """
    return HashingConfig().hash(model_path)


def sign(model_path: os.PathLike, signature_path: os.PathLike):
    """Signs a model using the default configuration.

    Args:
        model_path: the path to the model to sign.
        signature_path: the path of the resulting signature.
    """
    SigningConfig().sign(model_path, signature_path)


def verify(
    model_path: os.PathLike,
    signature_path: os.PathLike,
    *,
    identity: str,
    oidc_issuer: Optional[str] = None,
    use_staging: bool = False,
):
    """Verifies that a model conforms to a signature.

    Currently, this assumes signatures over DSSE, using Sigstore. We will add
    support for more cases in a future change.

    Args:
        model_path: the path to the model to verify.
        signature_path: the path to the signature to check.
        identity: The expected identity that has signed the model.
        oidc_issuer: The expected OpenID Connect issuer that provided the
          certificate used for the signature.
        use_staging: Use staging configurations, instead of production. This
          is supposed to be set to True only when testing. Default is False.
    """
    VerificationConfig().set_sigstore_dsse_verifier(
        identity=identity, oidc_issuer=oidc_issuer, use_staging=use_staging
    ).verify(model_path, signature_path)


class HashingConfig:
    """Configuration to use when hashing models.

    Hashing a model results in a `manifest.Manifest` object. This may contain a
    single digest for the entire model, or be a pairing between model components
    (e.g., files, file shards, etc.) and their corresponding hash.

    This configuration class allows selecting the serialization method to
    generate the desired manifest format.

    This configuration class also allows configuring files from within the model
    directory that should be ignored. These are files that doesn't impact the
    behavior of the model, or files that won't be distributed with the model.

    Note that currently this configuration class only supports the main options
    provided by the library. For more granular choices, usage of the lower level
    APIs is recommended.
    """

    def __init__(self):
        """Initializes the default configuration for hashing.

        The default hashing configuration uses SHA256 to compute the digest of
        every file in the model. The resulting manifest is a listing of files
        paired with their hashes. By default, no file is ignored and any
        symbolic link in the model directory results in an error.
        """
        self._ignored_paths = frozenset()
        self._serializer = serialize_by_file.ManifestSerializer(
            self._build_file_hasher_factory(), allow_symlinks=False
        )

    def hash(self, model_path: os.PathLike) -> manifest.Manifest:
        """Hashes a model using the current configuration."""
        return self._serializer.serialize(
            pathlib.Path(model_path), ignore_paths=self._ignored_paths
        )

    def _build_stream_hasher(
        self, hashing_algorithm: Literal["sha256", "blake2"] = "sha256"
    ) -> hashing.StreamingHashEngine:
        """Builds a streaming hasher from a constant string.

        Args:
            hashing_algorithm: the hashing algorithm to use.

        Returns:
            An instance of the requested hasher.
        """
        # TODO: Once Python 3.9 support is deprecated revert to using `match`
        if hashing_algorithm == "sha256":
            return memory.SHA256()
        if hashing_algorithm == "blake2":
            return memory.BLAKE2()

        raise ValueError(f"Unsupported hashing method {hashing_algorithm}")

    def _build_file_hasher_factory(
        self,
        hashing_algorithm: Literal["sha256", "blake2"] = "sha256",
        chunk_size: int = 8192,
    ) -> Callable[[pathlib.Path], file.SimpleFileHasher]:
        """Builds the hasher factory for a serialization by file.

        Args:
            hashing_algorithm: the hashing algorithm to use to hash a file
            chunk_size: The amount of file to read at once. Default is 8KB. A
              special value of 0 signals to attempt to read everything in a
              single call.

        Returns:
            The hasher factory that should be used by the active serialization
            method.
        """

        def factory(path: pathlib.Path) -> file.SimpleFileHasher:
            hasher = self._build_stream_hasher(hashing_algorithm)
            return file.SimpleFileHasher(path, hasher, chunk_size=chunk_size)

        return factory

    def _build_sharded_file_hasher_factory(
        self,
        hashing_algorithm: Literal["sha256", "blake2"] = "sha256",
        chunk_size: int = 8192,
        shard_size: int = 1000000,
    ) -> Callable[[pathlib.Path, int, int], file.ShardedFileHasher]:
        """Builds the hasher factory for a serialization by file shards.

        Args:
            hashing_algorithm: the hashing algorithm to use to hash a file
            chunk_size: The amount of file to read at once. Default is 8KB. A
              special value of 0 signals to attempt to read everything in a
              single call.
            shard_size: The size of a file shard. Default is 1,000,000 bytes.

        Returns:
            The hasher factory that should be used by the active serialization
            method.
        """
        algorithm = self._build_stream_hasher(hashing_algorithm)

        def factory(
            path: pathlib.Path, start: int, end: int
        ) -> file.ShardedFileHasher:
            return file.ShardedFileHasher(
                path,
                algorithm,
                start=start,
                end=end,
                chunk_size=chunk_size,
                shard_size=shard_size,
            )

        return factory

    def set_serialize_by_file_to_manifest(
        self,
        *,
        hashing_algorithm: Literal["sha256", "blake2"] = "sha256",
        chunk_size: int = 8192,
        max_workers: Optional[int] = None,
        allow_symlinks: bool = False,
    ) -> Self:
        """Configures serialization to a manifest pairing files with hashes.

        The serialization method in this configuration is changed to one where
        every file in the model is paired with its digest and a manifest
        containing all these pairings is being returned.

        Args:
            hashing_algorithm: the hashing algorithm to use to hash a file
            chunk_size: The amount of file to read at once. Default is 8KB. A
              special value of 0 signals to attempt to read everything in a
              single call.
            max_workers: Maximum number of workers to use in parallel. Default
              is to defer to the `concurrent.futures` library.
            allow_symlinks: Controls whether symbolic links are included. If a
              symlink is present but the flag is `False` (default) the
              serialization would raise an error.

        Returns:
            The new hashing configuration with the new serialization method.
        """
        self._serializer = serialize_by_file.ManifestSerializer(
            self._build_file_hasher_factory(hashing_algorithm, chunk_size),
            max_workers=max_workers,
            allow_symlinks=allow_symlinks,
        )
        return self

    def set_serialize_by_file_to_digest(
        self,
        *,
        hashing_algorithm: Literal["sha256", "blake2"] = "sha256",
        merge_algorithm: Literal["sha256", "blake2"] = "sha256",
        chunk_size: int = 8192,
        allow_symlinks: bool = False,
    ) -> Self:
        """Configures serialization to a single digest, at file granularity.

        The serialization method in this configuration is changed to one where
        every file in the model is paired with its digest and then a single
        digest is computed over this pairing.

        Args:
            hashing_algorithm: the hashing algorithm to use to hash a file
            merge_algorithm: the hashing algorithm to use when computing the
              final digest over all the (file, digest) pairings
            chunk_size: The amount of file to read at once. Default is 8KB. A
              special value of 0 signals to attempt to read everything in a
              single call.
            allow_symlinks: Controls whether symbolic links are included. If a
              symlink is present but the flag is `False` (default) the
              serialization would raise an error.

        Returns:
            The new hashing configuration with the new serialization method.
        """
        # TODO: https://github.com/sigstore/model-transparency/issues/197 -
        # Because the API for this case is different than the other ones, we
        # have to perform additional steps here.
        file_hasher = cast(
            file.SimpleFileHasher,
            self._build_file_hasher_factory(
                hashing_algorithm, chunk_size=chunk_size
            )(pathlib.Path("unused")),
        )
        merge_hasher = self._build_stream_hasher(merge_algorithm).__class__
        self._serializer = serialize_by_file.DigestSerializer(
            file_hasher, merge_hasher, allow_symlinks=allow_symlinks
        )
        return self

    def set_serialize_by_file_shard_to_manifest(
        self,
        *,
        hashing_algorithm: Literal["sha256", "blake2"] = "sha256",
        chunk_size: int = 8192,
        shard_size: int = 1000000,
        max_workers: Optional[int] = None,
        allow_symlinks: bool = False,
    ) -> Self:
        """Configures serialization to a manifest of (file shard, hash) pairs.

        The serialization method in this configuration is changed to one where
        every file in the model is sharded in equal sized shards and every shard
        is paired with its digest and a manifest containing all these pairings
        is being returned.

        Args:
            hashing_algorithm: the hashing algorithm to use to hash a file shard
            chunk_size: The amount of file to read at once. Default is 8KB. A
              special value of 0 signals to attempt to read everything in a
              single call.
            shard_size: The size of a file shard. Default is 1,000,000 bytes.
            max_workers: Maximum number of workers to use in parallel. Default
              is to defer to the `concurrent.futures` library.
            allow_symlinks: Controls whether symbolic links are included. If a
              symlink is present but the flag is `False` (default) the
              serialization would raise an error.

        Returns:
            The new hashing configuration with the new serialization method.
        """
        self._serializer = serialize_by_file_shard.ManifestSerializer(
            self._build_sharded_file_hasher_factory(
                hashing_algorithm, chunk_size, shard_size
            ),
            max_workers=max_workers,
            allow_symlinks=allow_symlinks,
        )
        return self

    def set_serialize_by_file_shard_to_digest(
        self,
        *,
        hashing_algorithm: Literal["sha256", "blake2"] = "sha256",
        merge_algorithm: Literal["sha256", "blake2"] = "sha256",
        chunk_size: int = 8192,
        shard_size: int = 1000000,
        max_workers: Optional[int] = None,
        allow_symlinks: bool = False,
    ) -> Self:
        """Configures serialization to a single digest, at shard granularity.

        The serialization method in this configuration is changed to one where
        every file shard in the model is paired with its digest and then a
        single digest is computed over all entries in this pairing.

        Args:
            hashing_algorithm: the hashing algorithm to use to hash a file shard
            merge_algorithm: the hashing algorithm to use when computing the
              final digest over all the (file, digest) pairings
            chunk_size: The amount of file to read at once. Default is 8KB. A
              special value of 0 signals to attempt to read everything in a
              single call.
            shard_size: The size of a file shard. Default is 1,000,000 bytes.
            max_workers: Maximum number of workers to use in parallel. Default
              is to defer to the `concurrent.futures` library.
            allow_symlinks: Controls whether symbolic links are included. If a
              symlink is present but the flag is `False` (default) the
              serialization would raise an error.

        Returns:
            The new hashing configuration with the new serialization method.
        """
        merge_hasher = self._build_stream_hasher(merge_algorithm)
        self._serializer = serialize_by_file_shard.DigestSerializer(
            self._build_sharded_file_hasher_factory(
                hashing_algorithm, chunk_size, shard_size
            ),
            merge_hasher,
            max_workers=max_workers,
            allow_symlinks=allow_symlinks,
        )
        return self

    def set_ignored_paths(self, paths: Iterable[os.PathLike]) -> Self:
        """Configures the paths to be ignored during serialization of a model.

        If the model is a single file, there are no paths that are ignored. If
        the model is a directory, all paths must be within the model directory.
        If a path to be ignored is absolute, we convert it to a path within the
        model directory during serialization. If the path is relative, it is
        assumed to be relative to the model root.

        If a path is a directory, serialization will ignore both the path and
        any of its children.

        Args:
            paths: the paths to ignore

        Returns:
            The new hashing configuration with a new set of ignored paths.
        """
        self._ignored_paths = frozenset({pathlib.Path(p) for p in paths})
        return self


class SigningConfig:
    """Configuration to use when signing models.

    The signing configuration is used to decouple between serialization formats
    and signing types. This configuration class allows setting up the
    serialization format, the method to convert a `manifest.Manifest` to a
    signing payload and the engine used for signing (currently, only supporting
    Sigstore at this level).
    """

    def __init__(self):
        """Initializes the default configuration for signing."""
        self._hashing_config = HashingConfig()
        self._payload_generator = in_toto.DigestsIntotoPayload.from_manifest
        self._signer = sigstore.SigstoreDSSESigner(
            use_ambient_credentials=False, use_staging=False
        )

    def sign(self, model_path: os.PathLike, signature_path: os.PathLike):
        """Signs a model using the current configuration.

        Args:
            model_path: the path to the model to sign.
            signature_path: the path of the resulting signature.
        """
        manifest = self._hashing_config.hash(model_path)
        payload = self._payload_generator(manifest)
        signature = self._signer.sign(payload)
        signature.write(pathlib.Path(signature_path))

    def set_hashing_config(self, hashing_config: HashingConfig) -> Self:
        """Sets the new configuration for hashing models.

        Args:
            hashing_config: the new hashing configuration.

        Returns:
            The new signing configuration.
        """
        self._hashing_config = hashing_config
        return self

    def set_payload_generator(
        self, generator: Callable[[manifest.Manifest], signing.SigningPayload]
    ) -> Self:
        """Sets the conversion from manifest to signing payload.

        Since we want to support multiple serialization formats and multiple
        signing solutions, we use a payload generator to relax the coupling
        between the two.

        Args:
            generator: the conversion function from a `manifest.Manifest` to a
              `signing.SigningPayload` payload.

        Return:
            The new signing configuration.
        """
        self._payload_generator = generator
        return self

    def set_sigstore_signer(
        self,
        *,
        sign_dsse: bool = True,
        oidc_issuer: Optional[str] = None,
        use_ambient_credentials: bool = True,
        use_staging: bool = False,
        identity_token: Optional[str] = None,
    ) -> Self:
        """Configures the signing to be performed with Sigstore.

        Only one signer can be configured. Currently, we only support Sigstore
        in the API, but the CLI supports signing with PKI, BYOK and no signing.
        We will merge the configurations in a subsequent change.

        Args:
            sign_dsse: Sign a DSSE statement (if True) or a binary blob.
            oidc_issuer: An optional OpenID Connect issuer to use instead of the
              default production one. Only relevant if `use_staging = False`.
              Default is empty, relying on the Sigstore configuration.
            use_ambient_credentials: Use ambient credentials (also known as
              Workload Identity). Default is True. If ambient credentials cannot
              be used (not available, or option disabled), a flow to get signer
              identity via OIDC will start.
            use_staging: Use staging configurations, instead of production. This
              is supposed to be set to True only when testing. Default is False.
            identity_token: An explicit identity token to use when signing,
              taking precedence over any ambient credential or OAuth workflow.

        Return:
            The new signing configuration.
        """
        if sign_dsse:
            signer_factory = sigstore.SigstoreDSSESigner
        else:
            signer_factory = sigstore.SigstoreArtifactSigner

        self._signer = signer_factory(
            oidc_issuer=oidc_issuer,
            use_ambient_credentials=use_ambient_credentials,
            use_staging=use_staging,
            identity_token=identity_token,
        )
        return self


class VerificationConfig:
    """Configuration to use when verifying models against signatures.

    The signing configuration is used to decouple between serialization formats
    and signing types. This configuration class allows setting up the
    serialization format, the method to convert a `manifest.Manifest` to a
    signing payload and the engine used for signing (currently, only supporting
    Sigstore at this level).
    """

    def __init__(self):
        """Initializes the default configuration for verification."""
        self._hashing_config = HashingConfig()
        self._verifier = None

    def verify(self, model_path: os.PathLike, signature_path: os.PathLike):
        """Verifies that a model conforms to a signature.

        Args:
            model_path: the path to the model to verify.
            signature_path: the path to the signature to check.
        """
        signature = sigstore.SigstoreSignature.read(
            pathlib.Path(signature_path)
        )
        expected_manifest = self._verifier.verify(signature)
        actual_manifest = self._hashing_config.hash(model_path)

        if actual_manifest != expected_manifest:
            raise ValueError("Signature mismatch")

    def set_hashing_config(self, hashing_config: HashingConfig) -> Self:
        """Sets the new configuration for hashing models.

        Args:
            hashing_config: the new hashing configuration.

        Returns:
            The new signing configuration.
        """
        self._hashing_config = hashing_config
        return self

    def set_sigstore_dsse_verifier(
        self,
        *,
        identity: str,
        oidc_issuer: Optional[str] = None,
        use_staging: bool = False,
    ) -> Self:
        """Configures the verification of a Sigstore signature over DSSE.

        Only one verifier can be configured. Currently, we only support Sigstore
        in the API, but the CLI supports signing with PKI, BYOK and no
        signing/verification.  We will merge the configurations in a subsequent
        change.

        Args:
            identity: The expected identity that has signed the model.
            oidc_issuer: The expected OpenID Connect issuer that provided the
              certificate used for the signature.
            use_staging: Use staging configurations, instead of production. This
              is supposed to be set to True only when testing. Default is False.

        Return:
            The new verification configuration.
        """
        self._verifier = sigstore.SigstoreDSSEVerifier(
            identity=identity, oidc_issuer=oidc_issuer, use_staging=use_staging
        )
        return self
