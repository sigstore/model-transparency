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

import base64
from collections.abc import Iterable
import logging
import pathlib

import certifi
from cryptography import exceptions
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import oid
from OpenSSL import crypto
from sigstore_models.bundle import v1 as bundle_pb
from sigstore_models.common import v1 as common_pb
from typing_extensions import override

from model_signing._signing import sign_ec_key as ec_key
from model_signing._signing import sign_sigstore_pb as sigstore_pb


logger = logging.getLogger(__name__)


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
                raw_bytes=base64.b64encode(
                    certificate.public_bytes(
                        encoding=serialization.Encoding.DER
                    )
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
            ),
            tlog_entries=[],
        )


def _log_certificate_fingerprint(
    where: str, certificate: x509.Certificate, hash_algorithm: hashes.Hash
) -> None:
    """Log the fingerprint of a certificate, for debugging.

    Args:
        where: Location of where this gets called from, useful for debugging.
        certificate: Certificate to compute fingerprint of and log.
        hash_algorithm: The algorithm used to compute the fingerprint.
    """
    fp = certificate.fingerprint(hash_algorithm)
    logger.info(
        f"[{where:^8}] {hash_algorithm.name} "
        f"Fingerprint: {':'.join(f'{b:02X}' for b in fp)}"
    )


class Verifier(sigstore_pb.Verifier):
    """Verifier for signatures generated via signing with certificates."""

    def __init__(
        self,
        certificate_chain_paths: Iterable[pathlib.Path] = frozenset(),
        log_fingerprints: bool = False,
    ):
        """Initializes the verifier with the list of certificates to use.

        Args:
            certificate_chain_paths: Paths to certificates used to verify
              signature and establish chain of trust. By default this is empty,
              in which case we would use the root certificates from the
              operating system, as per `certifi.where()`.
            log_fingerprints: Log the fingerprints of certificates
        """
        self._log_fingerprints = log_fingerprints

        if not certificate_chain_paths:
            certificate_chain_paths = [pathlib.Path(certifi.where())]

        certificates = x509.load_pem_x509_certificates(
            b"".join([path.read_bytes() for path in certificate_chain_paths])
        )

        self._store = crypto.X509Store()
        for certificate in certificates:
            if self._log_fingerprints:
                _log_certificate_fingerprint(
                    "init", certificate, hashes.SHA256()
                )
            self._store.add_cert(crypto.X509.from_cryptography(certificate))

    @override
    def _verify_bundle(self, bundle: bundle_pb.Bundle) -> tuple[str, bytes]:
        public_key = self._verify_certificates(bundle.verification_material)
        envelope = bundle.dsse_envelope
        try:
            public_key.verify(
                envelope.signatures[0].sig,
                sigstore_pb.pae(envelope.payload),
                ec.ECDSA(ec_key.get_ec_key_hash(public_key)),
            )
        except exceptions.InvalidSignature:
            # Compatibility layer with pre 1.0 release
            # Here, we patch over a bug in `pae` which mixed unicode `str` and
            # `bytes`. As a result, additional escape characters were added to
            # the material that got signed over.
            public_key.verify(
                envelope.signatures[0].sig,
                sigstore_pb.pae_compat(envelope.payload),
                # Note another bug here: the v0.2 signatures were generated with
                # hardcoded SHA256 hash, instead of the one that matches the
                # key type. To verify those signatures, we have to hardcode this
                # here too (instead of `ec_key.get_ec_key_hash(public_key)`).
                # For the hardcode path see:
                # https://github.com/sigstore/model-transparency/blob/9737f0e28349bf43897857ada7beaa22ec18e9a6/src/model_signing/signature/key.py#L103
                ec.ECDSA(hashes.SHA256()),
            )

        return envelope.payload_type, envelope.payload

    def _verify_certificates(
        self,
        verification_material: bundle_pb.VerificationMaterial,
        log_fingerprints: bool = False,
    ) -> ec.EllipticCurvePublicKey:
        """Verifies the certificate chain and returns the public key.

        The public key is extracted from the signing certificate from the chain
        of trust, after the chain is validated. It must match the public key
        from the key used during signing.
        """

        def _to_openssl_certificate(certificate_bytes, log_fingerprints):
            cert = x509.load_der_x509_certificate(certificate_bytes)
            if log_fingerprints:
                _log_certificate_fingerprint("verify", cert, hashes.SHA256())
            return crypto.X509.from_cryptography(cert)

        signing_chain = verification_material.x509_certificate_chain
        signing_certificate = x509.load_der_x509_certificate(
            signing_chain.certificates[0].raw_bytes
        )

        max_signing_time = signing_certificate.not_valid_before_utc
        self._store.set_time(max_signing_time)

        trust_chain_ssl = [
            _to_openssl_certificate(
                certificate.raw_bytes, self._log_fingerprints
            )
            for certificate in signing_chain.certificates[1:]
        ]
        signing_certificate_ssl = _to_openssl_certificate(
            signing_chain.certificates[0].raw_bytes, self._log_fingerprints
        )

        store_context = crypto.X509StoreContext(
            self._store, signing_certificate_ssl, trust_chain_ssl
        )
        store_context.verify_certificate()

        extensions = signing_certificate.extensions
        can_use_for_signing = False
        try:
            usage = extensions.get_extension_for_class(x509.KeyUsage)
            if usage.value.digital_signature:
                can_use_for_signing = True
        except x509.ExtensionNotFound:
            logger.warn("Certificate does not specify 'KeyUsage'.")

        if not can_use_for_signing:
            try:
                usage = extensions.get_extension_for_class(
                    x509.ExtendedKeyUsage
                )
                if oid.ExtendedKeyUsageOID.CODE_SIGNING in usage.value:
                    can_use_for_signing = True
            except x509.ExtensionNotFound:
                logger.warn("Certificate does not specify 'ExtendedKeyUsage'.")

        if not can_use_for_signing:
            raise ValueError("Signing certificate cannot be used for signing")

        return signing_certificate.public_key()
