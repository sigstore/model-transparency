# Copyright (c) 2024, NVIDIA CORPORATION.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Functionality to sign and verify models with certificates."""

from typing import Optional, Self

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import oid as crypto_oid
from in_toto_attestation.v1 import statement
from OpenSSL import crypto as ssl_crypto
from sigstore_protobuf_specs.dev.sigstore.bundle import v1 as bundle_pb
from sigstore_protobuf_specs.dev.sigstore.common import v1 as common_pb

from model_signing.signature.key import ECKeySigner
from model_signing.signature.key import ECKeyVerifier
from model_signing.signature.key import load_ec_private_key
from model_signing.signature.signing import Signer
from model_signing.signature.verifying import VerificationError
from model_signing.signature.verifying import Verifier


def _load_single_cert(path: str) -> x509.Certificate:
    with open(path, "rb") as fd:
        cert = x509.load_pem_x509_certificate(fd.read())
    return cert


def _load_multiple_certs(paths: list[str]) -> list[x509.Certificate]:
    certs = b""
    for p in paths:
        with open(p, "rb") as fd:
            certs += fd.read()
    return x509.load_pem_x509_certificates(certs)


class PKISigner(Signer):
    """Signer using an elliptic curve private key.

    The signer can be used for signing and adds the provided certificate
    information as verification material.
    """

    def __init__(
        self,
        private_key: ec.EllipticCurvePrivateKey,
        signing_cert: x509.Certificate,
        cert_chain: list[x509.Certificate],
    ) -> None:
        self._key_signer = ECKeySigner(private_key)
        self._signing_cert = signing_cert

        pub_key = private_key.public_key()
        cert_pub_key = self._signing_cert.public_key()
        if pub_key != cert_pub_key:
            raise ValueError(
                "the private key's public key does not match the"
                " signing certificates public key"
            )
        self._cert_chain = cert_chain

    @classmethod
    def from_path(
        cls,
        private_key_path: str,
        signing_cert_path: str,
        cert_chain_paths: list[str],
    ) -> Self:
        private_key = load_ec_private_key(private_key_path)
        signing_cert = _load_single_cert(signing_cert_path)
        cert_chain = _load_multiple_certs(cert_chain_paths)
        return cls(private_key, signing_cert, cert_chain)

    @staticmethod
    def __chain(
        signing_cert: x509.Certificate, chain: list[x509.Certificate]
    ) -> list[common_pb.X509Certificate]:
        result_chain = [
            common_pb.X509Certificate(
                raw_bytes=signing_cert.public_bytes(
                    encoding=serialization.Encoding.DER
                )
            )
        ]
        for cert in chain:
            result_chain.append(
                common_pb.X509Certificate(
                    raw_bytes=cert.public_bytes(
                        encoding=serialization.Encoding.DER
                    )
                )
            )
        return result_chain

    def sign(self, stmnt: statement.Statement) -> bundle_pb.Bundle:
        bdl = self._key_signer.sign(stmnt)
        bdl.verification_material.public_key = None
        bdl.verification_material.x509_certificate_chain = (
            common_pb.X509CertificateChain(
                certificates=self.__chain(self._signing_cert, self._cert_chain)
            )
        )
        return bdl


class PKIVerifier(Verifier):
    """Provides a verifier based on root certificates."""

    def __init__(
        self, root_certs: Optional[list[x509.Certificate]] = None
    ) -> None:
        self._store = ssl_crypto.X509Store()
        for c in root_certs:
            self._store.add_cert(ssl_crypto.X509.from_cryptography(c))

    @classmethod
    def from_paths(cls, root_cert_paths: Optional[list[str]] = None) -> Self:
        crypto_trust_roots: list[x509.Certificate] = []
        if root_cert_paths:
            crypto_trust_roots = _load_multiple_certs(root_cert_paths)
        else:
            crypto_trust_roots = _load_multiple_certs([certifi.where()])
        return cls(crypto_trust_roots)

    def verify(self, bundle: bundle_pb.Bundle) -> None:
        signing_chain = bundle.verification_material.x509_certificate_chain
        signing_cert_crypto = x509.load_der_x509_certificate(
            signing_chain.certificates[0].raw_bytes
        )
        sign_time = signing_cert_crypto.not_valid_before_utc
        self._store.set_time(sign_time)
        signing_cert_ossl = ssl_crypto.X509.from_cryptography(
            signing_cert_crypto
        )
        chain = []
        for cert in signing_chain.certificates[1:]:
            chain.append(
                ssl_crypto.X509.from_cryptography(
                    x509.load_der_x509_certificate(cert.raw_bytes)
                )
            )

        store_ctx = ssl_crypto.X509StoreContext(
            self._store, signing_cert_ossl, chain
        )
        try:
            store_ctx.verify_certificate()
        except ssl_crypto.X509StoreContextError as err:
            raise VerificationError(
                f"signing certificate verification failed: {err}"
            ) from err
        usage = signing_cert_crypto.extensions.get_extension_for_class(
            x509.KeyUsage
        )
        if not usage.value.digital_signature:
            raise VerificationError(
                "the certificate is not valid for digital signature usage"
            )
        ext_usage = signing_cert_crypto.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        )
        if crypto_oid.ExtendedKeyUsageOID.CODE_SIGNING not in ext_usage.value:
            raise VerificationError(
                "the certificate is not valid for code signing usage"
            )

        # Verify the contents with a key verifier
        pub_key: ec.EllipticCurvePublicKey = signing_cert_crypto.public_key
        verifier = ECKeyVerifier(pub_key)
        return verifier.verify(bundle)
