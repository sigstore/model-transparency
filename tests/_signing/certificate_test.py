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

"""Tests for SubjectAltName identity pinning in the certificate verifier."""

import datetime
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import oid
import pytest

from model_signing import hashing
from model_signing import signing
from model_signing import verifying


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
