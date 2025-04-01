# Copyright 2025 The Sigstore Authors
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

"""The main entry-point for the model_signing package."""

from collections.abc import Iterable, Sequence
import pathlib
from typing import Optional

import click

import model_signing
from model_signing import model
from model_signing._hashing import file
from model_signing._hashing import memory
from model_signing._serialization import serialize_by_file
from model_signing.signature import key
from model_signing.signature import pki
from model_signing.signing import in_toto
from model_signing.signing import in_toto_signature
from model_signing.signing import sign_sigstore as sigstore
from model_signing.signing import signing


# Decorator for the commonly used argument for the model path.
_model_path_argument = click.argument(
    "model_path", type=pathlib.Path, metavar="MODEL_PATH"
)


# Decorator for the commonly used option to set the signature path when signing.
_write_signature_option = click.option(
    "--signature",
    type=pathlib.Path,
    metavar="SIGNATURE_PATH",
    default=pathlib.Path("model.sig"),
    help="Location of the signature file to generate. Defaults to `model.sig`.",
)


# Decorator for the commonly used option for the signature to verify.
_read_signature_option = click.option(
    "--signature",
    type=pathlib.Path,
    metavar="SIGNATURE_PATH",
    required=True,
    help="Location of the signature file to verify.",
)

# Decorator for the commonly used option to ignore certain paths
_ignore_paths_option = click.option(
    "--ignore-paths",
    type=pathlib.Path,
    metavar="IGNORE_PATHS",
    multiple=True,
    help="File paths to ignore when signing or verifying.",
)

# Decorator for the commonly used option to ignore git-related paths
_ignore_git_paths_option = click.option(
    "--ignore-git-paths/--no-ignore-git-paths",
    type=bool,
    default=True,
    show_default=True,
    help="Ignore git-related files when signing or verifying.",
)

# Decorator for the commonly used option to set the path to the private key
# (when using non-Sigstore PKI).
_private_key_option = click.option(
    "--private_key",
    type=pathlib.Path,
    metavar="PRIVATE_KEY",
    required=True,
    help="Path to the private key, as a PEM-encoded file.",
)


# Decorator for the commonly used option to pass a certificate chain to
# establish root of trust (when signing or verifying using certificates).
_certificate_root_of_trust_option = click.option(
    "--certificate_chain",
    type=pathlib.Path,
    metavar="CERTIFICATE_PATH",
    multiple=True,
    help="Path to certificate chain of trust.",
)


def _collect_git_related_files(model_path: pathlib.Path) -> list[pathlib.Path]:
    """Expand to all git related files in the model directory."""
    return [pathlib.Path(p) for p in list(model_path.glob("**/.git*"))]


def _expand_paths_to_ignore(
    model_path: pathlib.Path,
    signature: pathlib.Path,
    ignore_paths: Iterable[pathlib.Path],
    ignore_git_paths: bool,
) -> list[pathlib.Path]:
    """Expand all ignore arguments to build the list of paths to exclude."""
    ignore_paths = [path for path in ignore_paths]
    ignore_paths.append(signature)
    if ignore_git_paths:
        ignore_paths.extend(_collect_git_related_files(model_path))
    return ignore_paths


class PKICmdGroup(click.Group):
    """A custom group to configure the supported PKI methods."""

    _supported_modes = ["sigstore", "key", "certificate"]

    def get_command(
        self, ctx: click.Context, cmd_name: str
    ) -> Optional[click.Command]:
        """Retrieves a command with a given name.

        We use this to make Sigstore signing be the default, if it is missing.
        """
        if cmd_name in self._supported_modes:
            return super().get_command(ctx, cmd_name)
        return super().get_command(ctx, "sigstore")

    def resolve_command(
        self, ctx: click.Context, args: Sequence[str]
    ) -> tuple[Optional[str], Optional[click.Command], Iterable[str]]:
        """Resolves a command and its arguments.

        We use this to make Sigstore signing be the default and correctly alter
        the arguments. We are guaranteed that `args` has at least one element
        (otherwise the help menu would be printed). This argument should be the
        subcommand and would be removed as a result of this function, in
        general.

        However, if the first argument does not resolve to a supported PKI
        method, then we inject "sigstore" as the subcommand (in `get_command`).
        All that is left to do is to pass all `args` to the subcommand, without
        removing anything.
        """
        if args[0] in self._supported_modes:
            return super().resolve_command(ctx, args)
        _, cmd, _ = super().resolve_command(ctx, args)
        return cmd.name, cmd, args


@click.group(
    context_settings=dict(help_option_names=["-h", "--help"]),
    epilog=(
        "Check https://sigstore.github.io/model-transparency for "
        "documentation and more details."
    ),
)
@click.version_option(model_signing.__version__, "--version")
def main() -> None:
    """ML model signing and verification.

    Use each subcommand's `--help` option for details on each mode.
    """


@main.group(name="sign", subcommand_metavar="PKI_METHOD", cls=PKICmdGroup)
def _sign() -> None:
    """Sign models.

    Produces a cryptographic signature (in the form of a Sigstore bundle) for a
    model. We support any model format, either as a single file or as a
    directory.

    We support multiple PKI methods, specified as subcommands. By default, the
    signature is generated via Sigstore (as if invoking `sigstore` subcommand).

    Use each subcommand's `--help` option for details on each mode.
    """


@_sign.command(name="sigstore")
@_model_path_argument
@_ignore_paths_option
@_ignore_git_paths_option
@_write_signature_option
@click.option(
    "--use_ambient_credentials",
    type=bool,
    is_flag=True,
    help="Use credentials from ambient environment.",
)
@click.option(
    "--identity_token",
    type=str,
    metavar="TOKEN",
    help=(
        "Fixed OIDC identity token to use instead of obtaining credentials "
        "from OIDC flow or from the environment."
    ),
)
@click.option(
    "--use_staging",
    type=bool,
    is_flag=True,
    help="Use Sigstore's staging instance.",
)
def _sign_sigstore(
    model_path: pathlib.Path,
    ignore_paths: Iterable[pathlib.Path],
    ignore_git_paths: bool,
    signature: pathlib.Path,
    use_ambient_credentials: bool,
    use_staging: bool,
    identity_token: Optional[str] = None,
) -> None:
    """Sign using Sigstore (DEFAULT signing method).

    Signing the model at MODEL_PATH, produces the signature at SIGNATURE_PATH
    (as per `--signature` option). Files in IGNORE_PATHS are not part of the
    signature.

    If using Sigstore, we need to provision an OIDC token. In general, this is
    taken from an interactive OIDC flow, but ambient credentials could be used
    to use workload identity tokens (e.g., when running in GitHub actions).
    Alternatively, a constant identity token can be provided via
    `--identity_token`.

    Sigstore allows users to use a staging instance for test-only signatures.
    Passing the `--use_staging` flag would use that instance instead of the
    production one.
    """
    signer = sigstore.SigstoreDSSESigner(
        use_ambient_credentials=use_ambient_credentials,
        use_staging=use_staging,
        identity_token=identity_token,
    )
    _serialize_and_sign(
        model_path, ignore_paths, ignore_git_paths, signer, signature
    )


@_sign.command(name="key")
@_model_path_argument
@_ignore_paths_option
@_ignore_git_paths_option
@_write_signature_option
@_private_key_option
def _sign_private_key(
    model_path: pathlib.Path,
    ignore_paths: Iterable[pathlib.Path],
    ignore_git_paths: bool,
    signature: pathlib.Path,
    private_key: pathlib.Path,
) -> None:
    """Sign using a private key (paired with a public one).

    Signing the model at MODEL_PATH, produces the signature at SIGNATURE_PATH
    (as per `--signature` option). Files in IGNORE_PATHS are not part of the
    signature.

    Traditionally, signing could be achieved by using a public/private key pair.
    Pass the signing key using `--private_key`.

    Note that this method does not provide a way to tie to the identity of the
    signer, outside of pairing the keys. Also note that we don't offer key
    management protocols.
    """
    signer = in_toto_signature.IntotoSigner(
        # TODO: The API needs clean up, it uses str, not pathlib.Path
        key.ECKeySigner.from_path(private_key_path=private_key.as_posix())
    )
    _serialize_and_sign(
        model_path, ignore_paths, ignore_git_paths, signer, signature
    )


@_sign.command(name="certificate")
@_model_path_argument
@_ignore_paths_option
@_ignore_git_paths_option
@_write_signature_option
@_private_key_option
@click.option(
    "--signing_certificate",
    type=pathlib.Path,
    metavar="CERTIFICATE_PATH",
    required=True,
    help="Path to the signing certificate, as a PEM-encoded file.",
)
@_certificate_root_of_trust_option
def _sign_certificate(
    model_path: pathlib.Path,
    ignore_paths: Iterable[pathlib.Path],
    ignore_git_paths: bool,
    signature: pathlib.Path,
    private_key: pathlib.Path,
    signing_certificate: pathlib.Path,
    certificate_chain: Iterable[pathlib.Path],
) -> None:
    """Sign using a certificate.

    Signing the model at MODEL_PATH, produces the signature at SIGNATURE_PATH
    (as per `--signature` option). Files in IGNORE_PATHS are not part of the
    signature.

    Traditionally, signing can be achieved by using keys from a certificate.
    The certificate can also provide the identity of the signer, making this
    method more informative than just using a public/private key pair for
    signing.  Pass the private signing key using `--private_key` and signing
    certificate via `--signing_certificate`. Optionally, pass a certificate
    chain via `--certificate_chain` to establish root of trust (this option can
    be repeated as needed, or all cerificates could be placed in a single file).

    Note that we don't offer certificate and key management protocols.
    """
    signer = in_toto_signature.IntotoSigner(
        # TODO: The API needs clean up, it uses str, not pathlib.Path
        pki.PKISigner.from_path(
            private_key.as_posix(),
            signing_certificate.as_posix(),
            [c.as_posix() for c in certificate_chain],
        )
    )
    _serialize_and_sign(
        model_path, ignore_paths, ignore_git_paths, signer, signature
    )


def _serialize_and_sign(
    model_path: pathlib.Path,
    ignore_paths: Iterable[pathlib.Path],
    ignore_git_paths: bool,
    signer: signing.Signer,
    signature: pathlib.Path,
) -> None:
    """Serialize a model and sign it with the provided signer."""

    def hasher_factory(file_path: pathlib.Path) -> file.FileHasher:
        return file.SimpleFileHasher(
            file=file_path, content_hasher=memory.SHA256()
        )

    serializer = serialize_by_file.Serializer(
        file_hasher_factory=hasher_factory
    )

    signing_result = model.sign(
        model_path=model_path,
        signer=signer,
        payload_generator=in_toto.DigestsIntotoPayload.from_manifest,
        serializer=serializer,
        ignore_paths=_expand_paths_to_ignore(
            model_path, signature, ignore_paths, ignore_git_paths
        ),
    )

    signing_result.write(signature)


@main.group(name="verify", subcommand_metavar="PKI_METHOD", cls=PKICmdGroup)
def _verify() -> None:
    """Verify models.

    Given a model and a cryptographic signature (in the form of a Sigstore
    bundle) for the model, this call checks that the model matches the
    signature, that the model has not been tampered with. We support any model
    format, either as a signle file or as a directory.

    We support multiple PKI methods, specified as subcommands. By default, the
    signature is assumed to be generated via Sigstore (as if invoking `sigstore`
    subcommand).

    Use each subcommand's `--help` option for details on each mode.
    """


@_verify.command(name="sigstore")
@_model_path_argument
@_read_signature_option
@_ignore_paths_option
@_ignore_git_paths_option
@click.option(
    "--identity",
    type=str,
    metavar="IDENTITY",
    required=True,
    help="The expected identity of the signer (e.g., name@example.com).",
)
@click.option(
    "--identity_provider",
    type=str,
    metavar="IDENTITY_PROVIDER",
    required=True,
    help="The expected identity provider (e.g., https://accounts.example.com).",
)
def _verify_sigstore(
    model_path: pathlib.Path,
    signature: pathlib.Path,
    ignore_paths: Iterable[pathlib.Path],
    ignore_git_paths: bool,
    identity: str,
    identity_provider: str,
) -> None:
    """Verify using Sigstore (DEFAULT verification method).

    Verifies the integrity of model at MODEL_PATH, according to signature from
    SIGNATURE_PATH (given via `--signature` option). Files in IGNORE_PATHS are
    ignored.

    For Sigstore, we also need to provide an expected identity and identity
    provider for the signature. If these don't match what is provided in the
    signature, verification would fail.
    """
    verifier = sigstore.SigstoreDSSEVerifier(
        identity=identity, oidc_issuer=identity_provider
    )
    signature_contents = sigstore.SigstoreSignature.read(signature)
    _serialize_and_verify(
        model_path,
        verifier,
        ignore_paths,
        ignore_git_paths,
        signature_contents,
        signature,
    )


@_verify.command(name="key")
@_model_path_argument
@_read_signature_option
@_ignore_paths_option
@_ignore_git_paths_option
@click.option(
    "--public_key",
    type=pathlib.Path,
    metavar="PUBLIC_KEY",
    required=True,
    help="Path to the public key used for verification.",
)
def _verify_private_key(
    model_path: pathlib.Path,
    signature: pathlib.Path,
    ignore_paths: Iterable[pathlib.Path],
    ignore_git_paths: bool,
    public_key: pathlib.Path,
) -> None:
    """Verity using a public key (paired with a private one).

    Verifies the integrity of model at MODEL_PATH, according to signature from
    SIGNATURE_PATH (given via `--signature` option). Files in IGNORE_PATHS are
    ignored.

    The public key provided via `--public_key` must have been paired with the
    private key used when generating the signature.

    Note that this method does not provide a way to tie to the identity of the
    signer, outside of pairing the keys. Also note that we don't offer key
    management protocols.
    """
    verifier = in_toto_signature.IntotoVerifier(
        # TODO: The API needs clean up, it uses str, not pathlib.Path
        key.ECKeyVerifier.from_path(public_key.as_posix())
    )
    signature_contents = in_toto_signature.IntotoSignature.read(signature)
    _serialize_and_verify(
        model_path,
        verifier,
        ignore_paths,
        ignore_git_paths,
        signature_contents,
        signature,
    )


@_verify.command(name="certificate")
@_model_path_argument
@_read_signature_option
@_ignore_paths_option
@_ignore_git_paths_option
@_certificate_root_of_trust_option
def _verify_certificate(
    model_path: pathlib.Path,
    signature: pathlib.Path,
    ignore_paths: Iterable[pathlib.Path],
    ignore_git_paths: bool,
    certificate_chain: Iterable[pathlib.Path],
) -> None:
    """Verify using a certificate.

    Verifies the integrity of model at MODEL_PATH, according to signature from
    SIGNATURE_PATH (given via `--signature` option). Files in IGNORE_PATHS are
    ignored.

    The signing certificate is encoded in the signature, as part of the Sigstore
    bundle. To verify the root of trust, pass additional certificates in the
    certificate chain, using `--certificate_chain` (this option can be repeated
    as needed, or all certificates could be placed in a single file).

    Note that we don't offer certificate and key management protocols.
    """
    verifier = in_toto_signature.IntotoVerifier(
        # TODO: The API needs clean up, it uses str, not pathlib.Path
        pki.PKIVerifier.from_paths([c.as_posix() for c in certificate_chain])
    )
    signature_contents = in_toto_signature.IntotoSignature.read(signature)
    _serialize_and_verify(
        model_path,
        verifier,
        ignore_paths,
        ignore_git_paths,
        signature_contents,
        signature,
    )


def _serialize_and_verify(
    model_path: pathlib.Path,
    verifier: signing.Verifier,
    ignore_paths: Iterable[pathlib.Path],
    ignore_git_paths: bool,
    signature_content: signing.Signature,
    signature_file: pathlib.Path,
) -> None:
    """Serialize a model and verify it with the provided verifier."""

    def hasher_factory(file_path: pathlib.Path) -> file.FileHasher:
        return file.SimpleFileHasher(
            file=file_path, content_hasher=memory.SHA256()
        )

    serializer = serialize_by_file.Serializer(
        file_hasher_factory=hasher_factory
    )

    try:
        model.verify(
            sig=signature_content,
            verifier=verifier,
            model_path=model_path,
            serializer=serializer,
            ignore_paths=_expand_paths_to_ignore(
                model_path, signature_file, ignore_paths, ignore_git_paths
            ),
        )
    except Exception as err:
        click.echo(f"Verification failed with error: {err}", err=True)
    else:
        click.echo("Verification succeeeded")
