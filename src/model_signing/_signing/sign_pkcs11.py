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

from collections.abc import Iterable
import pathlib
from typing import Optional

from asn1crypto.algos import DSASignature
from asn1crypto.core import OctetString
from asn1crypto.keys import ECDomainParameters
from asn1crypto.keys import PublicKeyInfo
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.protobuf import json_format
import PyKCS11
from sigstore_protobuf_specs.dev.sigstore.bundle import v1 as bundle_pb
from sigstore_protobuf_specs.dev.sigstore.common import v1 as common_pb
from sigstore_protobuf_specs.io import intoto as intoto_pb
from typing_extensions import override

from model_signing._signing import sign_ec_key as ec_key
from model_signing._signing import sign_sigstore_pb as sigstore_pb
from model_signing._signing import signing
from model_signing._signing.pkcs11uri import Pkcs11URI


MODULE_PATHS: Iterable[str] = [
    "/usr/lib64/pkcs11/",  # Fedora, RHEL, openSUSE
    "/usr/lib/pkcs11/",  # Fedora 32 bit, ArchLinux
]


def _check_supported_ec_key(public_key: ec.EllipticCurvePublicKey):
    """Checks if the elliptic curve key is supported by our package.

    We only support a family of curves, trying to match those specified by
    Sigstore's protobuf specs.
    See https://github.com/sigstore/model-transparency/issues/385.

    Args:
        public_key: The public key to check. Can be obtained from a private key.

    Raises:
        ValueError: The key is not supported.
    """
    curve = public_key.curve.name
    if curve not in ["secp256r1", "secp384r1", "secp521r1"]:
        raise ValueError(f"Unsupported key for curve '{curve}'")


def encode_ec_public_key(public_key: PyKCS11.CK_OBJECT_HANDLE) -> PublicKeyInfo:
    obj_d = public_key.to_dict()
    return PublicKeyInfo(
        {
            "algorithm": {
                "algorithm": "ec",
                "parameters": ECDomainParameters.load(
                    bytes(obj_d["CKA_EC_PARAMS"])
                ),
            },
            "public_key": bytes(OctetString.load(bytes(obj_d["CKA_EC_POINT"]))),
        }
    ).dump()


class Signer(sigstore_pb.Signer):
    """Signer using PKCS #11 URIs with elliptic curves keys."""

    def __init__(
        self, pkcs11_uri: str, module_paths: Iterable[str] = frozenset()
    ):
        self.session = None

        self.pkcs11_uri = Pkcs11URI()
        self.pkcs11_uri.parse(pkcs11_uri)

        if len(list(module_paths)) == 0:
            module_paths = MODULE_PATHS

        # To support module-name set a few standard paths
        self.pkcs11_uri.set_module_directories(module_paths)
        self.pkcs11_uri.set_allow_any_module(True)

        self.session, self.lib = self.pkcs11_uri.login()

        keyid, label = self.pkcs11_uri.get_keyid_and_label()

        self._private_key = self.find_object(
            PyKCS11.CKO_PRIVATE_KEY, label=label, id=keyid
        )
        public_key = self.find_object(
            PyKCS11.CKO_PUBLIC_KEY, label=label, id=keyid
        )
        pub_der = encode_ec_public_key(public_key)

        # _public_key is a python cryptography key now
        self._public_key = serialization.load_der_public_key(pub_der)
        _check_supported_ec_key(self._public_key)

    def __del__(self):
        if self.session:
            try:
                self.session.closeSession()
            finally:
                pass

    def public_key(self):
        """Get the python cryptography public key."""
        return self._public_key

    def find_object(
        self, clas: int, label: Optional[str], id: Optional[bytes]
    ) -> PyKCS11.CK_OBJECT_HANDLE:
        """Find an object given its class and optional label and id."""
        if label is None and id is None:
            raise ValueError(
                "Missing search criteria for object: either label or id must "
                "be provided in URI"
            )

        msg = ""
        if label is not None:
            msg = f"label {label}"
        if id is not None:
            if len(msg):
                msg += " and "
            msg += f"id {id}"

        cka_id = None
        if id is not None:
            cka_id = tuple([x for x in id])

        for obj in self.session.findObjects([(PyKCS11.CKA_CLASS, clas)]):
            obj_d = obj.to_dict()
            if label is not None and label != obj_d.get("CKA_LABEL"):
                continue
            if cka_id is not None and cka_id != obj_d.get("CKA_ID"):
                continue
            return obj
        raise ValueError(f"Could not find any object with {msg}")

    @override
    def sign(self, payload: signing.Payload) -> signing.Signature:
        raw_payload = json_format.MessageToJson(payload.statement.pb).encode(
            "utf-8"
        )

        hash_alg = ec_key.get_ec_key_hash(self._public_key)

        hash = hashes.Hash(hash_alg)
        hash.update(sigstore_pb.pae(raw_payload))
        digest = hash.finalize()

        rs_sig = self.session.sign(
            self._private_key,
            digest,
            mecha=PyKCS11.Mechanism(PyKCS11.CKM_ECDSA, None),
        )
        # Convert plain r & s signature values to ASN.1
        sig = DSASignature.from_p1363(rs_sig).dump()

        raw_signature = intoto_pb.Signature(sig=sig, keyid="")

        envelope = intoto_pb.Envelope(
            payload=raw_payload,
            payload_type=signing._IN_TOTO_JSON_PAYLOAD_TYPE,
            signatures=[raw_signature],
        )

        return sigstore_pb.Signature(
            bundle_pb.Bundle(
                media_type=sigstore_pb._BUNDLE_MEDIA_TYPE,
                verification_material=self._get_verification_material(),
                dsse_envelope=envelope,
            )
        )

    def _get_verification_material(self) -> bundle_pb.VerificationMaterial:
        """Returns the verification material to include in the bundle."""
        public_key = self._public_key
        key_size = public_key.curve.key_size

        # TODO: Once Python 3.9 support is deprecated revert to using `match`
        if key_size == 256:
            key_details = common_pb.PublicKeyDetails.PKIX_ECDSA_P256_SHA_256
        elif key_size == 384:
            key_details = common_pb.PublicKeyDetails.PKIX_ECDSA_P384_SHA_384
        elif key_size == 521:
            key_details = common_pb.PublicKeyDetails.PKIX_ECDSA_P521_SHA_512
        else:
            raise ValueError(f"Unexpected key size {key_size}")

        return bundle_pb.VerificationMaterial(
            public_key=common_pb.PublicKey(
                raw_bytes=public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
                key_details=key_details,
            )
        )


class CertSigner(Signer):
    """Signer using certificates."""

    def __init__(
        self,
        pkcs11_uri: str,
        signing_certificate_path: pathlib.Path,
        certificate_chain_paths: Iterable[pathlib.Path],
        module_paths: Iterable[str] = frozenset(),
    ):
        """Initializes the signer with the key, certificate and trust chain.

        Args:
            pkcs11_uri: The PKCS #11 URI.
            signing_certificate_path: The path to the signing certificate.
            certificate_chain_paths: Paths to other certificates used to
              establish chain of trust.

        Raises:
            ValueError: Signing certificate's public key does not match the
              private key's public pair.
        """
        super().__init__(pkcs11_uri, module_paths=module_paths)
        self._signing_certificate = x509.load_pem_x509_certificate(
            signing_certificate_path.read_bytes()
        )

        public_key_from_key = self._public_key
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
