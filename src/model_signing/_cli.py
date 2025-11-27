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
import contextlib
import logging
import pathlib
import sys

import click

import model_signing


class NoOpTracer:
    def start_as_current_span(self, name):
        @contextlib.contextmanager
        def noop_context():
            class NoOpSpan:
                def set_attribute(self, key, value):
                    pass

            yield NoOpSpan()

        return noop_context()


# Global tracer variable, we will initialized this within the main() function
tracer = None


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

# Decorator for the commonly used option for the custom trust configuration.
_trust_config_option = click.option(
    "--trust_config",
    type=pathlib.Path,
    metavar="TRUST_CONFIG_PATH",
    help="The client trust configuration to use",
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

# Decorator for the commonly used option to ignore all unsigned files
_ignore_unsigned_files_option = click.option(
    "--ignore_unsigned_files/--no-ignore_unsigned_files",
    type=bool,
    show_default=True,
    help="Ignore all files that were not originally signed.",
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

# Decorator for the commonly used option to set a PKCS #11 URI
_pkcs11_uri_option = click.option(
    "--pkcs11_uri",
    type=str,
    metavar="PKCS11_URI",
    required=True,
    help="PKCS #11 URI of the private key.",
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


# Decorator for the commonly used option to use Sigstore's staging instance.
_sigstore_staging_option = click.option(
    "--use_staging",
    type=bool,
    is_flag=True,
    help="Use Sigstore's staging instance.",
)

# Decorator for the commonly used option to pass the signing key's certificate
_signing_certificate_option = click.option(
    "--signing_certificate",
    type=pathlib.Path,
    metavar="CERTIFICATE_PATH",
    required=True,
    help="Path to the signing certificate, as a PEM-encoded file.",
)

# Decorator for the commonly used option to allow symlinks
_allow_symlinks_option = click.option(
    "--allow_symlinks",
    is_flag=True,
    help="Whether to allow following symlinks when signing or verifying files.",
)


def _resolve_ignore_paths(
    model_path: pathlib.Path, paths: Iterable[pathlib.Path]
) -> list[pathlib.Path]:
    model_root = model_path.resolve()
    cwd = pathlib.Path.cwd()
    resolved_paths = []
    for p in paths:
        candidate = (p if p.is_absolute() else (cwd / p)).resolve()
        try:
            resolved_paths.append(candidate.relative_to(model_root))
        except ValueError:
            continue
    return resolved_paths


class _PKICmdGroup(click.Group):
    """A custom group to configure the supported PKI methods."""

    _supported_modes = [
        "sigstore",
        "key",
        "certificate",
        "pkcs11-key",
        "pkcs11-certificate",
    ]

    def get_command(
        self, ctx: click.Context, cmd_name: str
    ) -> click.Command | None:
        """Retrieves a command with a given name.

        We use this to make Sigstore signing be the default, if it is missing.
        """
        if cmd_name in self._supported_modes:
            return super().get_command(ctx, cmd_name)
        return super().get_command(ctx, "sigstore")

    def resolve_command(
        self, ctx: click.Context, args: Sequence[str]
    ) -> tuple[str | None, click.Command | None, Iterable[str]]:
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
@click.option(
    "--log-level",
    type=click.Choice(
        ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], case_sensitive=False
    ),
    default="INFO",
    show_default=True,
    metavar="LEVEL",
    help="Set the logging level. This can also be set via the "
    "MODEL_SIGNING_LOG_LEVEL env var.",
)
def main(log_level: str) -> None:
    """ML model signing and verification.

    Use each subcommand's `--help` option for details on each mode.
    """
    global tracer

    logging.basicConfig(
        format="%(message)s", level=getattr(logging, log_level.upper())
    )

    try:
        from opentelemetry import trace  # type: ignore[import-error]
        from opentelemetry.instrumentation import (
            auto_instrumentation,  # type: ignore[import-error]
        )

        auto_instrumentation.initialize()
        tracer = trace.get_tracer(__name__)
    except ImportError:
        logging.debug("OpenTelemetry not installed. Tracing is disabled.")
        tracer = NoOpTracer()
    except Exception as e:
        logging.error(
            f"Failed to initialize OpenTelemetry auto instrumentation: {e}"
        )
        sys.exit(1)


@main.group(name="sign", subcommand_metavar="PKI_METHOD", cls=_PKICmdGroup)
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
@_allow_symlinks_option
@_write_signature_option
@_sigstore_staging_option
@_trust_config_option
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
    "--oauth_force_oob",
    is_flag=True,
    default=False,
    help=(
        "Force an out-of-band OAuth flow and do not automatically start "
        "the default web browser."
    ),
)
@click.option(
    "--client_id",
    type=str,
    metavar="ID",
    help="The custom OpenID Connect client ID to use during OAuth2",
)
@click.option(
    "--client_secret",
    type=str,
    metavar="SECRET",
    help="The custom OpenID Connect client secret to use during OAuth2",
)
def _sign_sigstore(
    model_path: pathlib.Path,
    ignore_paths: Iterable[pathlib.Path],
    ignore_git_paths: bool,
    allow_symlinks: bool,
    signature: pathlib.Path,
    use_ambient_credentials: bool,
    use_staging: bool,
    oauth_force_oob: bool,
    identity_token: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    trust_config: pathlib.Path | None = None,
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

    Additionally, you can specify a custom trust configuration JSON file using
    the `--trust_config` flag. This allows you to fully customize the PKI
    (Private Key Infrastructure) used in the signing process. By providing a
    `--trust_config`, you can define your own transparency logs, certificate
    authorities, and other trust settings, enabling full control over the
    trust model, including which PKI to use for signature verification.

    If `--trust_config` is not provided, the default Sigstore instance is
    used, which is pre-configured with Sigstore’s own trusted transparency
    logs and certificate authorities. This provides a ready-to-use default
    trust model for most use cases but may not be suitable for custom or
    highly regulated environments.
    """
    with tracer.start_as_current_span("Sign") as span:
        span.set_attribute("sigstore.sign_method", "sigstore")
        span.set_attribute("sigstore.model_path", str(model_path))
        span.set_attribute("sigstore.signature", str(signature))
        span.set_attribute(
            "sigstore.use_ambient_credentials", use_ambient_credentials
        )
        span.set_attribute("sigstore.use_staging", use_staging)
        try:
            ignored = _resolve_ignore_paths(
                model_path, list(ignore_paths) + [signature]
            )
            model_signing.signing.Config().use_sigstore_signer(
                use_ambient_credentials=use_ambient_credentials,
                use_staging=use_staging,
                identity_token=identity_token,
                force_oob=oauth_force_oob,
                client_id=client_id,
                client_secret=client_secret,
                trust_config=trust_config,
            ).set_hashing_config(
                model_signing.hashing.Config()
                .set_ignored_paths(
                    paths=ignored, ignore_git_paths=ignore_git_paths
                )
                .set_allow_symlinks(allow_symlinks)
            ).sign(model_path, signature)
        except Exception as err:
            click.echo(f"Signing failed with error: {err}", err=True)
            sys.exit(1)

        click.echo("Signing succeeded")


@_sign.command(name="key")
@_model_path_argument
@_ignore_paths_option
@_ignore_git_paths_option
@_allow_symlinks_option
@_write_signature_option
@_private_key_option
@click.option(
    "--password",
    type=str,
    metavar="PASSWORD",
    help="Password for the key encryption, if any",
)
def _sign_private_key(
    model_path: pathlib.Path,
    ignore_paths: Iterable[pathlib.Path],
    ignore_git_paths: bool,
    allow_symlinks: bool,
    signature: pathlib.Path,
    private_key: pathlib.Path,
    password: str | None = None,
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
    try:
        ignored = _resolve_ignore_paths(
            model_path, list(ignore_paths) + [signature]
        )
        model_signing.signing.Config().use_elliptic_key_signer(
            private_key=private_key, password=password
        ).set_hashing_config(
            model_signing.hashing.Config()
            .set_ignored_paths(paths=ignored, ignore_git_paths=ignore_git_paths)
            .set_allow_symlinks(allow_symlinks)
        ).sign(model_path, signature)
    except Exception as err:
        click.echo(f"Signing failed with error: {err}", err=True)
        sys.exit(1)

    click.echo("Signing succeeded")


@_sign.command(name="pkcs11-key")
@_model_path_argument
@_ignore_paths_option
@_ignore_git_paths_option
@_allow_symlinks_option
@_write_signature_option
@_pkcs11_uri_option
def _sign_pkcs11_key(
    model_path: pathlib.Path,
    ignore_paths: Iterable[pathlib.Path],
    ignore_git_paths: bool,
    allow_symlinks: bool,
    signature: pathlib.Path,
    pkcs11_uri: str,
) -> None:
    """Sign using a private key using a PKCS #11 URI.

    Signing the model at MODEL_PATH, produces the signature at SIGNATURE_PATH
    (as per `--signature` option). Files in IGNORE_PATHS are not part of the
    signature.

    Traditionally, signing could be achieved by using a public/private key pair.
    Pass the PKCS #11 URI of the signing key using `--pkcs11_uri`.

    Note that this method does not provide a way to tie to the identity of the
    signer, outside of pairing the keys. Also note that we don't offer key
    management protocols.
    """
    try:
        ignored = _resolve_ignore_paths(
            model_path, list(ignore_paths) + [signature]
        )
        model_signing.signing.Config().use_pkcs11_signer(
            pkcs11_uri=pkcs11_uri
        ).set_hashing_config(
            model_signing.hashing.Config()
            .set_ignored_paths(paths=ignored, ignore_git_paths=ignore_git_paths)
            .set_allow_symlinks(allow_symlinks)
        ).sign(model_path, signature)
    except Exception as err:
        click.echo(f"Signing failed with error: {err}", err=True)
        sys.exit(1)

    click.echo("Signing succeeded")


@_sign.command(name="certificate")
@_model_path_argument
@_ignore_paths_option
@_ignore_git_paths_option
@_allow_symlinks_option
@_write_signature_option
@_private_key_option
@_signing_certificate_option
@_certificate_root_of_trust_option
def _sign_certificate(
    model_path: pathlib.Path,
    ignore_paths: Iterable[pathlib.Path],
    ignore_git_paths: bool,
    allow_symlinks: bool,
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
    try:
        ignored = _resolve_ignore_paths(
            model_path, list(ignore_paths) + [signature]
        )
        model_signing.signing.Config().use_certificate_signer(
            private_key=private_key,
            signing_certificate=signing_certificate,
            certificate_chain=certificate_chain,
        ).set_hashing_config(
            model_signing.hashing.Config()
            .set_ignored_paths(paths=ignored, ignore_git_paths=ignore_git_paths)
            .set_allow_symlinks(allow_symlinks)
        ).sign(model_path, signature)
    except Exception as err:
        click.echo(f"Signing failed with error: {err}", err=True)
        sys.exit(1)

    click.echo("Signing succeeded")


@_sign.command(name="pkcs11-certificate")
@_model_path_argument
@_ignore_paths_option
@_ignore_git_paths_option
@_allow_symlinks_option
@_write_signature_option
@_pkcs11_uri_option
@_signing_certificate_option
@_certificate_root_of_trust_option
def _sign_pkcs11_certificate(
    model_path: pathlib.Path,
    ignore_paths: Iterable[pathlib.Path],
    ignore_git_paths: bool,
    allow_symlinks: bool,
    signature: pathlib.Path,
    pkcs11_uri: str,
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
    signing. Pass the PKCS #11 URI of the private signing key using
    `--pkcs11_uri` and then signing certificate via `--signing_certificate`.
    Optionally, pass a certificate chain via `--certificate_chain` to establish
    root of trust (this option can be repeated as needed, or all cerificates
    could be placed in a single file).

    Note that we don't offer certificate and key management protocols.
    """
    try:
        ignored = _resolve_ignore_paths(
            model_path, list(ignore_paths) + [signature]
        )
        model_signing.signing.Config().use_pkcs11_certificate_signer(
            pkcs11_uri=pkcs11_uri,
            signing_certificate=signing_certificate,
            certificate_chain=certificate_chain,
        ).set_hashing_config(
            model_signing.hashing.Config()
            .set_ignored_paths(paths=ignored, ignore_git_paths=ignore_git_paths)
            .set_allow_symlinks(allow_symlinks)
        ).sign(model_path, signature)
    except Exception as err:
        click.echo(f"Signing failed with error: {err}", err=True)
        sys.exit(1)

    click.echo("Signing succeeded")


@main.group(name="verify", subcommand_metavar="PKI_METHOD", cls=_PKICmdGroup)
def _verify() -> None:
    """Verify models.

    Given a model and a cryptographic signature (in the form of a Sigstore
    bundle) for the model, this call checks that the model matches the
    signature, that the model has not been tampered with. We support any model
    format, either as a signle file or as a directory.

    We support multiple PKI methods, specified as subcommands. By default, the
    signature is assumed to be generated via Sigstore (as if invoking `sigstore`
    subcommand).

    To enable verification with custom PKI configurations, use the
    `--trust_config` option. This allows you to specify your own set of trusted
    public keys, transparency logs, and certificate authorities for verifying
    the signature. If not provided, the default Sigstore instance and its
    associated public keys, logs, and authorities are used.

    Use each subcommand's `--help` option for details on each mode.
    """


@_verify.command(name="sigstore")
@_model_path_argument
@_read_signature_option
@_ignore_paths_option
@_ignore_git_paths_option
@_allow_symlinks_option
@_sigstore_staging_option
@_trust_config_option
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
@_ignore_unsigned_files_option
def _verify_sigstore(
    model_path: pathlib.Path,
    signature: pathlib.Path,
    ignore_paths: Iterable[pathlib.Path],
    ignore_git_paths: bool,
    allow_symlinks: bool,
    identity: str,
    identity_provider: str,
    use_staging: bool,
    ignore_unsigned_files: bool,
    trust_config: pathlib.Path | None = None,
) -> None:
    """Verify using Sigstore (DEFAULT verification method).

    Verifies the integrity of model at MODEL_PATH, according to signature from
    SIGNATURE_PATH (given via `--signature` option). Files in IGNORE_PATHS are
    ignored.

    For Sigstore, we also need to provide an expected identity and identity
    provider for the signature. If these don't match what is provided in the
    signature, verification would fail.
    """
    with tracer.start_as_current_span("Verify") as span:
        span.set_attribute("sigstore.method", "sigstore")
        span.set_attribute("sigstore.model_path", str(model_path))
        span.set_attribute("sigstore.signature", str(signature))
        span.set_attribute("sigstore.identity", identity)
        span.set_attribute("sigstore.oidc_issuer", identity_provider)
        span.set_attribute("sigstore.use_staging", use_staging)
        try:
            ignored = _resolve_ignore_paths(
                model_path, list(ignore_paths) + [signature]
            )
            model_signing.verifying.Config().use_sigstore_verifier(
                identity=identity,
                oidc_issuer=identity_provider,
                use_staging=use_staging,
                trust_config=trust_config,
            ).set_hashing_config(
                model_signing.hashing.Config()
                .set_ignored_paths(
                    paths=ignored, ignore_git_paths=ignore_git_paths
                )
                .set_allow_symlinks(allow_symlinks)
            ).set_ignore_unsigned_files(ignore_unsigned_files).verify(
                model_path, signature
            )
        except Exception as err:
            click.echo(f"Verification failed with error: {err}", err=True)
            sys.exit(1)

        click.echo("Verification succeeded")


@_verify.command(name="key")
@_model_path_argument
@_read_signature_option
@_ignore_paths_option
@_ignore_git_paths_option
@_allow_symlinks_option
@click.option(
    "--public_key",
    type=pathlib.Path,
    metavar="PUBLIC_KEY",
    required=True,
    help="Path to the public key used for verification.",
)
@_ignore_unsigned_files_option
def _verify_private_key(
    model_path: pathlib.Path,
    signature: pathlib.Path,
    ignore_paths: Iterable[pathlib.Path],
    ignore_git_paths: bool,
    allow_symlinks: bool,
    public_key: pathlib.Path,
    ignore_unsigned_files: bool,
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
    try:
        ignored = _resolve_ignore_paths(
            model_path, list(ignore_paths) + [signature]
        )
        model_signing.verifying.Config().use_elliptic_key_verifier(
            public_key=public_key
        ).set_hashing_config(
            model_signing.hashing.Config()
            .set_ignored_paths(paths=ignored, ignore_git_paths=ignore_git_paths)
            .set_allow_symlinks(allow_symlinks)
        ).set_ignore_unsigned_files(ignore_unsigned_files).verify(
            model_path, signature
        )
    except Exception as err:
        click.echo(f"Verification failed with error: {err}", err=True)
        sys.exit(1)

    click.echo("Verification succeeded")


@_verify.command(name="certificate")
@_model_path_argument
@_read_signature_option
@_ignore_paths_option
@_ignore_git_paths_option
@_allow_symlinks_option
@_certificate_root_of_trust_option
@click.option(
    "--log_fingerprints",
    type=bool,
    is_flag=True,
    default=False,
    show_default=True,
    help="Log SHA256 fingerprints of all certificates.",
)
@_ignore_unsigned_files_option
def _verify_certificate(
    model_path: pathlib.Path,
    signature: pathlib.Path,
    ignore_paths: Iterable[pathlib.Path],
    ignore_git_paths: bool,
    allow_symlinks: bool,
    certificate_chain: Iterable[pathlib.Path],
    log_fingerprints: bool,
    ignore_unsigned_files: bool,
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
    if log_fingerprints:
        logging.basicConfig(format="%(message)s", level=logging.INFO)

    try:
        ignored = _resolve_ignore_paths(
            model_path, list(ignore_paths) + [signature]
        )
        model_signing.verifying.Config().use_certificate_verifier(
            certificate_chain=certificate_chain,
            log_fingerprints=log_fingerprints,
        ).set_hashing_config(
            model_signing.hashing.Config()
            .set_ignored_paths(paths=ignored, ignore_git_paths=ignore_git_paths)
            .set_allow_symlinks(allow_symlinks)
        ).set_ignore_unsigned_files(ignore_unsigned_files).verify(
            model_path, signature
        )
    except Exception as err:
        click.echo(f"Verification failed with error: {err}", err=True)
        sys.exit(1)

    click.echo("Verification succeeded")
