# Copyright (c) 2025, IBM CORPORATION.  All rights reserved.
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

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hashes import SHA384
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from sigstore_protobuf_specs.dev.sigstore.common import v1 as common_pb


def get_ec_key_params(
    public_key: ec.EllipticCurvePublicKey,
) -> tuple[HashAlgorithm, common_pb.PublicKeyDetails]:
    key_size = public_key.curve.key_size
    if key_size == 256:
        return SHA256(), common_pb.PublicKeyDetails.PKIX_ECDSA_P256_SHA_256
    elif key_size == 384:
        return SHA384(), common_pb.PublicKeyDetails.PKIX_ECDSA_P384_SHA_384
    elif key_size == 521:
        return SHA512(), common_pb.PublicKeyDetails.PKIX_ECDSA_P521_SHA_512
    raise ValueError(f"Unexpected key size {key_size}")


def check_supported_ec_key(public_key: ec.EllipticCurvePublicKey):
    curve = public_key.curve.name
    if curve not in ["secp256r1", "secp384r1", "secp521r1"]:
        raise ValueError(f"Unsupported key for curve '{curve}'")
