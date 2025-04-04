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

"""Signers and verifiers using certificates."""

from collections.abc import Iterable
import pathlib

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import oid
from OpenSSL import crypto
from sigstore_protobuf_specs.dev.sigstore.bundle import v1 as bundle_pb
from sigstore_protobuf_specs.dev.sigstore.common import v1 as common_pb
from typing_extensions import override

from model_signing._signing import sign_ec_key as ec_key
from model_signing._signing import sign_sigstore_pb as sigstore_pb


class Signer(ec_key.Signer):
    """Signer using certificates."""

    def __init__(
        self,
        private_key_path: pathlib.Path,
        signing_certificate_path: pathlib.Path,
        certificate_chain_paths: Iterable[pathlib.Path],
    ):
        """Initializes the signer with the key, certificate and trust chain.

        Args:
            private_key_path: The path to the PEM encoded private key.
            signing_certificate_path: The path to the signing certificate.
            certificate_chain_paths: Paths to other certificates used to
              establish chain of trust.

        Raises:
            ValueError: Signing certificate's public key does not match the
              private key's public pair.
        """
        super().__init__(private_key_path)
        self._signing_certificate = x509.load_pem_x509_certificate(
            signing_certificate_path.read_bytes()
        )

        public_key_from_key = self._private_key.public_key()
        public_key_from_certificate = self._signing_certificate.public_key()
        if public_key_from_key != public_key_from_certificate:
            raise ValueError(
                "The public key from the certificate does not match "
                "the public key paired with the private key"
            )

        self._trust_chain = x509.load_pem_x509_certificates(
            b"".join([path.read_bytes() for path in certificate_chain_paths])
        )

    @override
    def _get_verification_material(self) -> bundle_pb.VerificationMaterial:
        def _to_protobuf_certificate(certificate):
            return common_pb.X509Certificate(
                raw_bytes=certificate.public_bytes(
                    encoding=serialization.Encoding.DER
                )
            )

        chain = [_to_protobuf_certificate(self._signing_certificate)]
        chain.extend(
            [
                _to_protobuf_certificate(certificate)
                for certificate in self._trust_chain
            ]
        )

        return bundle_pb.VerificationMaterial(
            x509_certificate_chain=common_pb.X509CertificateChain(
                certificates=chain
            )
        )


class Verifier(sigstore_pb.Verifier):
    """Verifier for signatures generated via signing with certificates."""

    def __init__(
        self, certificate_chain_paths: Iterable[pathlib.Path] = frozenset()
    ):
        """Initializes the verifier with the list of certificates to use.

        Args:
            certificate_chain_paths: Paths to certificates used to verify
              signature and establish chain of trust. By default this is empty,
              in which case we would use the root certificates from the
              operating system, as per `certifi.where()`.
        """
        if not certificate_chain_paths:
            certificate_chain_paths = [pathlib.Path(p) for p in certifi.where()]

        certificates = x509.load_pem_x509_certificates(
            b"".join([path.read_bytes() for path in certificate_chain_paths])
        )

        self._store = crypto.X509Store()
        for certificate in certificates:
            self._store.add_cert(crypto.X509.from_cryptography(certificate))

    @override
    def _verify_bundle(self, bundle: bundle_pb.Bundle) -> tuple[str, bytes]:
        public_key = self._verify_certificates(bundle.verification_material)
        envelope = bundle.dsse_envelope
        public_key.verify(
            envelope.signatures[0].sig,
            sigstore_pb.pae(envelope.payload),
            ec.ECDSA(ec_key.get_ec_key_hash(public_key)),
        )

        return envelope.payload_type, envelope.payload

    def _verify_certificates(
        self, verification_material: bundle_pb.VerificationMaterial
    ) -> ec.EllipticCurvePublicKey:
        """Verifies the certificate chain and returns the public key.

        The public key is extracted from the signing certificate from the chain
        of trust, after the chain is validated. It must match the public key
        from the key used during signing.
        """

        def _to_openssl_certificate(certificate_bytes):
            return crypto.X509.from_cryptography(
                x509.load_der_x509_certificate(certificate_bytes)
            )

        signing_chain = verification_material.x509_certificate_chain
        signing_certificate = x509.load_der_x509_certificate(
            signing_chain.certificates[0].raw_bytes
        )

        max_signing_time = signing_certificate.not_valid_before
        self._store.set_time(max_signing_time)

        signing_certificate_ssl = _to_openssl_certificate(
            signing_chain.certificates[0].raw_bytes
        )
        trust_chain_ssl = [
            _to_openssl_certificate(certificate.raw_bytes)
            for certificate in signing_chain.certificates[1:]
        ]
        store_context = crypto.X509StoreContext(
            self._store, signing_certificate_ssl, trust_chain_ssl
        )
        store_context.verify_certificate()

        extensions = signing_certificate.extensions
        can_use_for_signing = False
        usage = extensions.get_extension_for_class(x509.KeyUsage)
        if usage.value.digital_signature:
            can_use_for_signing = True
        else:
            try:
                usage = extensions.get_extension_for_class(
                    x509.ExtendedKeyUsage
                )
                if oid.ExtendedKeyUsageOID.CODE_SIGNING in usage.value:
                    can_use_for_signing = True
            except x509.ExtensionNotFound:
                pass

        if not can_use_for_signing:
            raise ValueError("Signing certificate cannot be used for signing")

        return signing_certificate.public_key()
