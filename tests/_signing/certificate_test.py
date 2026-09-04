# Copyright 2026 The Sigstore Authors
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

"""Tests for the certificate verifier."""

import base64
import datetime
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import oid
import pytest
from sigstore_models.bundle import v1 as bundle_pb
from sigstore_models.common import v1 as common_pb

from model_signing import hashing
from model_signing import signing
from model_signing import verifying
from model_signing._signing import sign_certificate as certificate


_SAN_URI = "spiffe://demo.example.com/signer/demo"
_OTHER_URI = "spiffe://demo.example.com/signer/other"


def _issue_chain(
    tmp_path: pathlib.Path,
    san_uris: list[str],
) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    """Issue a self-signed CA + a leaf cert with the requested URI SANs.

    Returns (private_key_pem, leaf_cert_pem, ca_cert_pem).
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([
        x509.NameAttribute(oid.NameOID.COMMON_NAME, "Demo Root CA"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name([
        x509.NameAttribute(oid.NameOID.COMMON_NAME, "demo-signer"),
    ])
    san = x509.SubjectAlternativeName(
        [x509.UniformResourceIdentifier(u) for u in san_uris]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
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
            x509.ExtendedKeyUsage([oid.ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )
    )
    if san_uris:
        builder = builder.add_extension(san, critical=False)
    leaf_cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    key_path = tmp_path / "leaf.key"
    key_path.write_bytes(
        leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    leaf_path = tmp_path / "leaf.cert"
    leaf_path.write_bytes(
        leaf_cert.public_bytes(encoding=serialization.Encoding.PEM)
    )
    ca_path = tmp_path / "ca.cert"
    ca_path.write_bytes(
        ca_cert.public_bytes(encoding=serialization.Encoding.PEM)
    )
    return key_path, leaf_path, ca_path


def _sign_blob(
    tmp_path: pathlib.Path,
    key_path: pathlib.Path,
    leaf_path: pathlib.Path,
    ca_path: pathlib.Path,
) -> tuple[pathlib.Path, pathlib.Path]:
    """Sign a small model and return (model_path, signature_path)."""
    model_path = tmp_path / "model.bin"
    model_path.write_bytes(b"hello, model_signing")
    signature = tmp_path / "model.sig"
    signing.Config().use_certificate_signer(
        private_key=key_path,
        signing_certificate=leaf_path,
        certificate_chain=[ca_path],
    ).set_hashing_config(
        hashing.Config().set_ignored_paths(paths=[signature])
    ).sign(model_path, signature)
    return model_path, signature


class TestVerifyCertificateSanIdentity:
    """Identity pinning via `expected_san_uris` (e.g. SPIFFE SVID URI SAN)."""

    def test_matching_uri_verifies(self, tmp_path):
        key, leaf, ca = _issue_chain(tmp_path, [_SAN_URI])
        model, sig = _sign_blob(tmp_path, key, leaf, ca)
        verifying.Config().use_certificate_verifier(
            certificate_chain=[ca], expected_san_uris=[_SAN_URI]
        ).set_hashing_config(
            hashing.Config().set_ignored_paths(paths=[sig])
        ).verify(model, sig)

    def test_no_expected_identity_still_verifies(self, tmp_path):
        # Back-compat: without pinning, the check is skipped entirely.
        key, leaf, ca = _issue_chain(tmp_path, [_SAN_URI])
        model, sig = _sign_blob(tmp_path, key, leaf, ca)
        verifying.Config().use_certificate_verifier(
            certificate_chain=[ca]
        ).set_hashing_config(
            hashing.Config().set_ignored_paths(paths=[sig])
        ).verify(model, sig)

    def test_wrong_uri_rejected(self, tmp_path):
        key, leaf, ca = _issue_chain(tmp_path, [_SAN_URI])
        model, sig = _sign_blob(tmp_path, key, leaf, ca)
        with pytest.raises(ValueError, match="missing expected URI"):
            verifying.Config().use_certificate_verifier(
                certificate_chain=[ca], expected_san_uris=[_OTHER_URI]
            ).set_hashing_config(
                hashing.Config().set_ignored_paths(paths=[sig])
            ).verify(model, sig)

    def test_no_san_in_leaf_rejected_when_pinning_requested(self, tmp_path):
        key, leaf, ca = _issue_chain(tmp_path, [])
        model, sig = _sign_blob(tmp_path, key, leaf, ca)
        with pytest.raises(ValueError, match="no SubjectAlternativeName"):
            verifying.Config().use_certificate_verifier(
                certificate_chain=[ca], expected_san_uris=[_SAN_URI]
            ).set_hashing_config(
                hashing.Config().set_ignored_paths(paths=[sig])
            ).verify(model, sig)

    def test_cross_signer_attack_rejected(self, tmp_path):
        """A different leaf under the same CA must not satisfy identity pin."""
        good = tmp_path / "good"
        good.mkdir()
        bad = tmp_path / "bad"
        bad.mkdir()
        # We can't share the CA private key across helper calls, so we
        # simulate the shared-CA scenario by issuing two independent CAs and
        # verifying the bad-signer bundle against the bad-signer CA (chain
        # verification succeeds), while pinning the good-signer URI
        # (identity check must fail).
        _issue_chain(good, [_SAN_URI])
        bad_key, bad_leaf, bad_ca = _issue_chain(bad, [_OTHER_URI])
        model, sig = _sign_blob(bad, bad_key, bad_leaf, bad_ca)
        with pytest.raises(ValueError, match="missing expected URI"):
            verifying.Config().use_certificate_verifier(
                certificate_chain=[bad_ca], expected_san_uris=[_SAN_URI]
            ).set_hashing_config(
                hashing.Config().set_ignored_paths(paths=[sig])
            ).verify(model, sig)


def _name(common_name):
    return x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, common_name)])


def _mint(extended_key_usages):
    """Mints a private root and a leaf carrying the given extended key usages.

    The leaf always sets the digitalSignature key usage bit. Passing `None` for
    the extended key usages omits the ExtendedKeyUsage extension entirely.

    Returns:
        A tuple of the root certificate and the leaf certificate.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = (
        x509.CertificateBuilder()
        .subject_name(_name("test-root"))
        .issuer_name(_name("test-root"))
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(root_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name("test-leaf"))
        .issuer_name(root.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
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
    )
    if extended_key_usages is not None:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(extended_key_usages), critical=False
        )
    leaf = builder.sign(root_key, hashes.SHA256())
    return root, leaf


def _material(leaf):
    der = leaf.public_bytes(serialization.Encoding.DER)
    return bundle_pb.VerificationMaterial(
        x509_certificate_chain=common_pb.X509CertificateChain(
            certificates=[
                common_pb.X509Certificate(raw_bytes=base64.b64encode(der))
            ]
        ),
        tlog_entries=[],
    )


def _verifier(root, tmp_path):
    root_pem = tmp_path / "root.pem"
    root_pem.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    return certificate.Verifier(certificate_chain_paths=[root_pem])


class TestCertificateExtendedKeyUsage:
    def test_rejects_non_code_signing_eku(self, tmp_path):
        # A TLS (serverAuth) certificate must not be usable for model signing,
        # even though it carries the digitalSignature key usage bit.
        root, leaf = _mint([oid.ExtendedKeyUsageOID.SERVER_AUTH])
        verifier = _verifier(root, tmp_path)
        with pytest.raises(ValueError, match="cannot be used for signing"):
            verifier._verify_certificates(_material(leaf))

    def test_accepts_code_signing_eku(self, tmp_path):
        root, leaf = _mint([oid.ExtendedKeyUsageOID.CODE_SIGNING])
        verifier = _verifier(root, tmp_path)
        public_key = verifier._verify_certificates(_material(leaf))
        assert isinstance(public_key, ec.EllipticCurvePublicKey)

    def test_accepts_missing_eku(self, tmp_path):
        root, leaf = _mint(None)
        verifier = _verifier(root, tmp_path)
        public_key = verifier._verify_certificates(_material(leaf))
        assert isinstance(public_key, ec.EllipticCurvePublicKey)


def _mint_with_validity(
    root_not_before,
    root_not_after,
    leaf_not_before,
    leaf_not_after,
    inter_not_before=None,
    inter_not_after=None,
):
    """Mint a cert chain with explicit validity periods.

    Returns (root_cert, leaf_cert, leaf_key, [intermediate_cert]) or
    (root_cert, leaf_cert, leaf_key, []) if no intermediate is requested.
    """
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = (
        x509.CertificateBuilder()
        .subject_name(_name("test-root"))
        .issuer_name(_name("test-root"))
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(root_not_before)
        .not_valid_after(root_not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(root_key, hashes.SHA256())
    )

    issuer_key = root_key
    issuer_name = root.subject
    intermediates = []

    if inter_not_before is not None and inter_not_after is not None:
        inter_key = ec.generate_private_key(ec.SECP256R1())
        inter = (
            x509.CertificateBuilder()
            .subject_name(_name("test-intermediate"))
            .issuer_name(root.subject)
            .public_key(inter_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(inter_not_before)
            .not_valid_after(inter_not_after)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0), critical=True
            )
            .sign(root_key, hashes.SHA256())
        )
        issuer_key = inter_key
        issuer_name = inter.subject
        intermediates = [inter]

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_name("test-leaf"))
        .issuer_name(issuer_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(leaf_not_before)
        .not_valid_after(leaf_not_after)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
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
            x509.ExtendedKeyUsage([oid.ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )
    return root, leaf, leaf_key, intermediates


def _write_pem(path, cert_or_key, is_key=False):
    if is_key:
        path.write_bytes(cert_or_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    else:
        path.write_bytes(cert_or_key.public_bytes(serialization.Encoding.PEM))


class TestCertificateValidity:
    """Certificate validity period checks for signing and verification."""

    _NOW = datetime.datetime.now(datetime.timezone.utc)
    _VALID = (_NOW - datetime.timedelta(days=365), _NOW + datetime.timedelta(days=365))
    _EXPIRED = (_NOW - datetime.timedelta(days=730), _NOW - datetime.timedelta(days=365))
    _NOT_YET = (_NOW + datetime.timedelta(days=365), _NOW + datetime.timedelta(days=730))

    def _sign_and_verify(self, tmp_path, root, leaf, leaf_key, intermediates):
        _write_pem(tmp_path / "root.pem", root)
        _write_pem(tmp_path / "leaf.pem", leaf)
        _write_pem(tmp_path / "leaf.key", leaf_key, is_key=True)
        inter_paths = []
        for i, inter in enumerate(intermediates):
            p = tmp_path / f"inter{i}.pem"
            _write_pem(p, inter)
            inter_paths.append(p)

        model = tmp_path / "model"
        model.mkdir()
        (model / "data.txt").write_text("test content")
        sig = tmp_path / "model.sig"

        signing.Config().use_certificate_signer(
            private_key=str(tmp_path / "leaf.key"),
            signing_certificate=str(tmp_path / "leaf.pem"),
            certificate_chain=[str(p) for p in inter_paths],
        ).sign(model, sig)

        verifying.Config().use_certificate_verifier(
            certificate_chain=[str(tmp_path / "root.pem")],
        ).verify(model, sig)

    def _try_sign(self, tmp_path, root, leaf, leaf_key, intermediates):
        _write_pem(tmp_path / "root.pem", root)
        _write_pem(tmp_path / "leaf.pem", leaf)
        _write_pem(tmp_path / "leaf.key", leaf_key, is_key=True)
        inter_paths = []
        for i, inter in enumerate(intermediates):
            p = tmp_path / f"inter{i}.pem"
            _write_pem(p, inter)
            inter_paths.append(p)

        model = tmp_path / "model"
        model.mkdir()
        (model / "data.txt").write_text("test content")
        sig = tmp_path / "model.sig"

        signing.Config().use_certificate_signer(
            private_key=str(tmp_path / "leaf.key"),
            signing_certificate=str(tmp_path / "leaf.pem"),
            certificate_chain=[str(p) for p in inter_paths],
        ).sign(model, sig)

    # --- Baseline: all valid ---

    def test_all_valid_passes(self, tmp_path):
        root, leaf, leaf_key, _ = _mint_with_validity(
            *self._VALID, *self._VALID
        )
        self._sign_and_verify(tmp_path, root, leaf, leaf_key, [])

    def test_all_valid_with_intermediate_passes(self, tmp_path):
        root, leaf, leaf_key, inters = _mint_with_validity(
            *self._VALID, *self._VALID,
            inter_not_before=self._VALID[0], inter_not_after=self._VALID[1],
        )
        self._sign_and_verify(tmp_path, root, leaf, leaf_key, inters)

    # --- Signing rejects expired/not-yet-valid leaf ---

    def test_signing_rejects_expired_leaf(self, tmp_path):
        root, leaf, leaf_key, _ = _mint_with_validity(
            *self._VALID, *self._EXPIRED
        )
        with pytest.raises(ValueError, match="certificate has expired"):
            self._try_sign(tmp_path, root, leaf, leaf_key, [])

    def test_signing_rejects_not_yet_valid_leaf(self, tmp_path):
        root, leaf, leaf_key, _ = _mint_with_validity(
            *self._VALID, *self._NOT_YET
        )
        with pytest.raises(ValueError, match="not yet valid"):
            self._try_sign(tmp_path, root, leaf, leaf_key, [])

    def test_signing_rejects_expired_leaf_with_intermediate(self, tmp_path):
        root, leaf, leaf_key, inters = _mint_with_validity(
            *self._VALID, *self._EXPIRED,
            inter_not_before=self._VALID[0], inter_not_after=self._VALID[1],
        )
        with pytest.raises(ValueError, match="certificate has expired"):
            self._try_sign(tmp_path, root, leaf, leaf_key, inters)

    # --- Verification rejects expired certs in the chain ---

    def test_verification_rejects_expired_root(self, tmp_path):
        root, leaf, leaf_key, _ = _mint_with_validity(
            *self._EXPIRED, *self._VALID
        )
        _write_pem(tmp_path / "root.pem", root)
        _write_pem(tmp_path / "leaf.pem", leaf)
        _write_pem(tmp_path / "leaf.key", leaf_key, is_key=True)

        model = tmp_path / "model"
        model.mkdir()
        (model / "data.txt").write_text("test content")
        sig = tmp_path / "model.sig"

        signing.Config().use_certificate_signer(
            private_key=str(tmp_path / "leaf.key"),
            signing_certificate=str(tmp_path / "leaf.pem"),
            certificate_chain=[],
        ).sign(model, sig)

        with pytest.raises(Exception):
            verifying.Config().use_certificate_verifier(
                certificate_chain=[str(tmp_path / "root.pem")],
            ).verify(model, sig)

    def test_verification_rejects_expired_intermediate(self, tmp_path):
        root, leaf, leaf_key, inters = _mint_with_validity(
            *self._VALID, *self._VALID,
            inter_not_before=self._EXPIRED[0], inter_not_after=self._EXPIRED[1],
        )
        _write_pem(tmp_path / "root.pem", root)
        _write_pem(tmp_path / "leaf.pem", leaf)
        _write_pem(tmp_path / "leaf.key", leaf_key, is_key=True)
        _write_pem(tmp_path / "inter.pem", inters[0])

        model = tmp_path / "model"
        model.mkdir()
        (model / "data.txt").write_text("test content")
        sig = tmp_path / "model.sig"

        signing.Config().use_certificate_signer(
            private_key=str(tmp_path / "leaf.key"),
            signing_certificate=str(tmp_path / "leaf.pem"),
            certificate_chain=[str(tmp_path / "inter.pem")],
        ).sign(model, sig)

        with pytest.raises(Exception):
            verifying.Config().use_certificate_verifier(
                certificate_chain=[str(tmp_path / "root.pem")],
            ).verify(model, sig)

    def test_verification_rejects_not_yet_valid_intermediate(self, tmp_path):
        root, leaf, leaf_key, inters = _mint_with_validity(
            *self._VALID, *self._VALID,
            inter_not_before=self._NOT_YET[0], inter_not_after=self._NOT_YET[1],
        )
        _write_pem(tmp_path / "root.pem", root)
        _write_pem(tmp_path / "leaf.pem", leaf)
        _write_pem(tmp_path / "leaf.key", leaf_key, is_key=True)
        _write_pem(tmp_path / "inter.pem", inters[0])

        model = tmp_path / "model"
        model.mkdir()
        (model / "data.txt").write_text("test content")
        sig = tmp_path / "model.sig"

        signing.Config().use_certificate_signer(
            private_key=str(tmp_path / "leaf.key"),
            signing_certificate=str(tmp_path / "leaf.pem"),
            certificate_chain=[str(tmp_path / "inter.pem")],
        ).sign(model, sig)

        with pytest.raises(Exception):
            verifying.Config().use_certificate_verifier(
                certificate_chain=[str(tmp_path / "root.pem")],
            ).verify(model, sig)

    def test_verification_rejects_all_expired(self, tmp_path):
        root, leaf, leaf_key, _ = _mint_with_validity(
            *self._EXPIRED, *self._EXPIRED
        )
        with pytest.raises(ValueError, match="certificate has expired"):
            self._try_sign(tmp_path, root, leaf, leaf_key, [])

    # --- Boundary cases ---

    def test_signing_rejects_recently_expired_cert(self, tmp_path):
        now = datetime.datetime.now(datetime.timezone.utc)
        root, leaf, leaf_key, _ = _mint_with_validity(
            *self._VALID,
            now - datetime.timedelta(days=365),
            now - datetime.timedelta(seconds=30),
        )
        with pytest.raises(ValueError, match="certificate has expired"):
            self._try_sign(tmp_path, root, leaf, leaf_key, [])

    def test_signing_rejects_cert_not_yet_valid_soon(self, tmp_path):
        now = datetime.datetime.now(datetime.timezone.utc)
        root, leaf, leaf_key, _ = _mint_with_validity(
            *self._VALID,
            now + datetime.timedelta(seconds=30),
            now + datetime.timedelta(days=365),
        )
        with pytest.raises(ValueError, match="not yet valid"):
            self._try_sign(tmp_path, root, leaf, leaf_key, [])

    def test_signing_rejects_zero_length_expired_cert(self, tmp_path):
        now = datetime.datetime.now(datetime.timezone.utc)
        instant = now - datetime.timedelta(days=1)
        root, leaf, leaf_key, _ = _mint_with_validity(
            *self._VALID, instant, instant
        )
        with pytest.raises(ValueError, match="certificate has expired"):
            self._try_sign(tmp_path, root, leaf, leaf_key, [])

    # --- Verifier direct API (bypassing signer to test independently) ---

    def test_verify_certificates_rejects_expired_leaf(self, tmp_path):
        root, leaf, _, _ = _mint_with_validity(
            *self._VALID, *self._EXPIRED
        )
        _write_pem(tmp_path / "root.pem", root)
        verifier = certificate.Verifier(
            certificate_chain_paths=[tmp_path / "root.pem"]
        )
        with pytest.raises(Exception):
            verifier._verify_certificates(_material(leaf))

    def test_verify_certificates_rejects_all_same_expired_window(self, tmp_path):
        """Regression: when all certs share the same expired validity window,
        the old set_time(not_valid_before) trick made everything pass."""
        root, leaf, _, _ = _mint_with_validity(
            *self._EXPIRED, *self._EXPIRED
        )
        _write_pem(tmp_path / "root.pem", root)
        verifier = certificate.Verifier(
            certificate_chain_paths=[tmp_path / "root.pem"]
        )
        with pytest.raises(Exception):
            verifier._verify_certificates(_material(leaf))

    def test_verify_certificates_rejects_not_yet_valid_leaf(self, tmp_path):
        root, leaf, _, _ = _mint_with_validity(
            *self._VALID, *self._NOT_YET
        )
        _write_pem(tmp_path / "root.pem", root)
        verifier = certificate.Verifier(
            certificate_chain_paths=[tmp_path / "root.pem"]
        )
        with pytest.raises(Exception):
            verifier._verify_certificates(_material(leaf))
