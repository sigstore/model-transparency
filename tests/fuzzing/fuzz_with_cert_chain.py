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

import datetime as dt
from pathlib import Path
import shutil
import sys
import tempfile

import atheris  # type: ignore
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import NameOID
from utils import create_fuzz_files

from model_signing import hashing
from model_signing import signing
from model_signing import verifying


def _rand_utf8(
    fdp: atheris.FuzzedDataProvider, min_len: int = 1, max_len: int = 32
) -> str:
    n = fdp.ConsumeIntInRange(min_len, max_len)
    data = fdp.ConsumeBytes(n)
    if not data:
        return "x"
    s = "".join(chr(32 + (c % 95)) for c in data).strip()
    return s or "x"


def gen_private_key(fdp: atheris.FuzzedDataProvider):
    """Generate RSA or EC private key using fuzz data (for CAs)."""
    if fdp.ConsumeBool():
        curve = fdp.PickValueInList(
            [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()]
        )
        return ec.generate_private_key(curve)
    key_size = fdp.PickValueInList([1024, 2048])
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def gen_ec_key(fdp: atheris.FuzzedDataProvider):
    """Generate an EC private key (for the leaf)."""
    curve = fdp.PickValueInList(
        [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()]
    )
    return ec.generate_private_key(curve)


def gen_name(fdp: atheris.FuzzedDataProvider) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, _rand_utf8(fdp, 3, 40))]
    if fdp.ConsumeBool():
        attrs.append(
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME, _rand_utf8(fdp, 2, 20)
            )
        )
    if fdp.ConsumeBool():
        attrs.append(
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, _rand_utf8(fdp, 2, 20)
            )
        )
    if fdp.ConsumeBool():
        cb = fdp.ConsumeBytes(2) or b"US"
        country = "".join(chr(ord("A") + (b % 26)) for b in cb)
        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    if fdp.ConsumeBool():
        attrs.append(
            x509.NameAttribute(NameOID.LOCALITY_NAME, _rand_utf8(fdp, 2, 20))
        )
    return x509.Name(attrs)


def _ski(public_key) -> x509.SubjectKeyIdentifier:
    return x509.SubjectKeyIdentifier.from_public_key(public_key)


def deterministic_serial(fdp: atheris.FuzzedDataProvider) -> int:
    """Deterministic, positive serial (≤159 bits, non-zero) from input."""
    length = fdp.ConsumeIntInRange(1, 20)
    b = fdp.ConsumeBytes(length)
    if not b:
        b = b"\x01"
    val = int.from_bytes(b, "big") & ((1 << 159) - 1)
    return val or 1


def deterministic_validity(
    fdp: atheris.FuzzedDataProvider,
) -> tuple[dt.datetime, dt.datetime]:
    """Validity window derived solely from fuzz input (no wall clock)."""
    base = dt.datetime(2000, 1, 1, tzinfo=dt.timezone.utc)
    start_days = fdp.ConsumeIntInRange(0, 9000)
    not_before = base + dt.timedelta(days=start_days)
    lifetime_days = fdp.ConsumeIntInRange(30, 3650)
    not_after = not_before + dt.timedelta(days=lifetime_days)
    return not_before, not_after


def _pick_sig_hash(fdp: atheris.FuzzedDataProvider):
    return fdp.PickValueInList(
        [hashes.SHA256(), hashes.SHA384(), hashes.SHA512()]
    )


def build_valid_chain(
    fdp: atheris.FuzzedDataProvider,
) -> tuple[x509.Certificate, object, list[x509.Certificate]]:
    """Build a valid chain: root -> 0..3 intermediates -> leaf (depth 1..5).

    Returns (leaf_cert, leaf_key, issuers_chain) where issuers_chain is
    [nearest_intermediate, ..., root] and does NOT include the leaf.
    """
    depth = fdp.ConsumeIntInRange(1, 5)
    not_before, not_after = deterministic_validity(fdp)

    # Root CA
    root_key = gen_private_key(fdp)
    root_name = gen_name(fdp)
    root_builder = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(deterministic_serial(fdp))
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=depth - 1), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(_ski(root_key.public_key()), critical=False)
    )
    root_cert = root_builder.sign(
        private_key=root_key, algorithm=_pick_sig_hash(fdp)
    )

    issuer_key = root_key
    issuer_cert = root_cert
    issuers: list[x509.Certificate] = [root_cert]

    # Intermediates
    for i in range(depth - 1):
        key = gen_private_key(fdp)
        name = gen_name(fdp)
        inter_builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(issuer_cert.subject)
            .public_key(key.public_key())
            .serial_number(deterministic_serial(fdp))
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=(depth - 2 - i)),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(_ski(key.public_key()), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    x509.SubjectKeyIdentifier.from_public_key(
                        issuer_key.public_key()
                    )
                ),
                critical=False,
            )
        )
        inter_cert = inter_builder.sign(
            private_key=issuer_key, algorithm=_pick_sig_hash(fdp)
        )
        issuer_key = key
        issuer_cert = inter_cert
        issuers.insert(0, inter_cert)  # nearest first

    # Leaf (code signing) — ALWAYS EC to satisfy signer expectations
    leaf_key = gen_ec_key(fdp)
    leaf_name = gen_name(fdp)
    leaf_builder = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(issuer_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(deterministic_serial(fdp))
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )
        .add_extension(_ski(leaf_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                x509.SubjectKeyIdentifier.from_public_key(
                    issuer_key.public_key()
                )
            ),
            critical=False,
        )
    )
    leaf_cert = leaf_builder.sign(
        private_key=issuer_key, algorithm=_pick_sig_hash(fdp)
    )

    return leaf_cert, leaf_key, issuers


def to_pem_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(encoding=serialization.Encoding.PEM)


def key_to_pem(priv: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _build_hashing_config_from_fdp(
    fdp: atheris.FuzzedDataProvider,
    extra_ignores: list[Path],
    signature_path: Path,
) -> hashing.Config:
    alg = ["sha256", "blake2", "blake3"][fdp.ConsumeIntInRange(0, 2)]
    hcfg = hashing.Config().set_ignored_paths(
        paths=[*list(extra_ignores), signature_path],
        ignore_git_paths=fdp.ConsumeBool(),
    )
    if fdp.ConsumeBool():
        hcfg.use_file_serialization(hashing_algorithm=alg)
    else:
        hcfg.use_shard_serialization(hashing_algorithm=alg)
    return hcfg


def TestOneInput(data: bytes):
    fdp = atheris.FuzzedDataProvider(data)

    # 1) Build certs & keys (catch x509 construction errors)
    try:
        leaf_cert, leaf_key, issuers = build_valid_chain(fdp)
    except (
        ValueError,
        TypeError,
        x509.DuplicateExtension,
        x509.UnsupportedGeneralNameType,
        UnsupportedAlgorithm,
    ):
        return  # skip this testcase; invalid X.509

    # 2) Convert to PEM and write to disk (catch serialization errors)
    workdir = tempfile.mkdtemp(prefix="fuzz_cert_")
    try:
        leaf_key_path = Path(workdir) / "leaf-key.pem"
        leaf_cert_path = Path(workdir) / "leaf-cert.pem"
        chain_paths: list[Path] = []

        with open(leaf_key_path, "wb") as f:
            f.write(key_to_pem(leaf_key))
        with open(leaf_cert_path, "wb") as f:
            f.write(to_pem_cert(leaf_cert))

        for idx, cert in enumerate(issuers):
            p = Path(workdir) / f"chain-{idx}.pem"
            with open(p, "wb") as f:
                f.write(to_pem_cert(cert))
            chain_paths.append(p)

        # Check chain length before signing and verifying
        if len(chain_paths) <= 1:
            shutil.rmtree(workdir, ignore_errors=True)
            return

    except (ValueError, TypeError, UnsupportedAlgorithm):
        shutil.rmtree(workdir, ignore_errors=True)
        return

    # 3) Create model files
    model_path_dir = tempfile.mkdtemp(prefix="fuzz_model_")
    model_path_p = Path(model_path_dir)
    created_files = create_fuzz_files(model_path_p, fdp)
    if created_files == 0:
        return

    # Signature output path (we ignore this when signing and verifying)
    fname = f"signature-{_rand_utf8(fdp, 3, 12).replace('/', '_')}.sig"
    signature_path = model_path_p / fname

    # Ignores (collected for hashing config)
    extra_ignores: list[Path] = []

    # Build hashing config (serialization + algorithm + ignores)
    hcfg = _build_hashing_config_from_fdp(fdp, extra_ignores, signature_path)

    # 4) Sign and 5) Verify
    try:
        signing.Config().use_certificate_signer(
            private_key=leaf_key_path,
            signing_certificate=leaf_cert_path,
            certificate_chain=chain_paths,
        ).set_hashing_config(hcfg).sign(model_path_p, signature_path)

        verifying.Config().use_certificate_verifier(
            certificate_chain=chain_paths, log_fingerprints=False
        ).set_hashing_config(hcfg).verify(model_path_p, signature_path)

    finally:
        # Always clean up temp dirs
        shutil.rmtree(model_path_dir, ignore_errors=True)
        shutil.rmtree(workdir, ignore_errors=True)


def main() -> None:
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
