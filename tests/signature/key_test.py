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
# flake8: noqa: E712
import pathlib

from in_toto_attestation.v1 import resource_descriptor as res_desc
from in_toto_attestation.v1 import statement
import pytest

from model_signing.signature.key import ECKeySigner
from model_signing.signature.key import ECKeyVerifier
from model_signing.signature.verifying import VerificationError


_PRIV_KEY_1 = b"""-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIDcpvDIigb10Ys3SbkoAd+yquWkiu/GW4Qx495pnsZh4oAcGBSuBBAAK
oUQDQgAEU+HLGtq3jwrv3i3oT7pq3NAMnfoWBuPOeeiZOl32+7dpuhkbXs4nTDSC
kUd2RjIbO7kAeFjJfMpmZEgMwkH/dw==
-----END EC PRIVATE KEY-----
"""
_PUB_KEY_1 = b"""-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEU+HLGtq3jwrv3i3oT7pq3NAMnfoWBuPO
eeiZOl32+7dpuhkbXs4nTDSCkUd2RjIbO7kAeFjJfMpmZEgMwkH/dw==
-----END PUBLIC KEY-----
"""
_PUB_KEY_2 = b"""-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEITXyGcKk9nf7Hy2hrjEvGfhaNLGV5mPI
vqTAE4riBlZztzGudZajfAA6UVsrBHoBdHPvkxegmSIsTs9YWl68mA==
-----END PUBLIC KEY-----
"""


def __dump_keys(path: pathlib.Path) -> tuple[str, str]:
    priv_key_path = path.joinpath("private.pem")
    priv_key_path.write_bytes(_PRIV_KEY_1)
    pub_key_path = path.joinpath("public.pem")
    pub_key_path.write_bytes(_PUB_KEY_1)
    return str(priv_key_path), str(pub_key_path)


def __get_stmnt() -> statement.Statement:
    return statement.Statement(
        subjects=[
            res_desc.ResourceDescriptor(
                name="abc", digest={"myhash": b"12345"}
            ).pb,
            res_desc.ResourceDescriptor(
                name="def", digest={"myhash": b"67890"}
            ).pb,
            res_desc.ResourceDescriptor(
                name="ghi", digest={"myhash": b"11111"}
            ).pb,
        ],
        predicate_type="model_signing/v1",
        predicate={"name": "unknown"},
    )


def test_key_signature_success(tmp_path: pathlib.Path):
    priv_key_path, pub_key_path = __dump_keys(tmp_path)

    stmnt = __get_stmnt()

    signer = ECKeySigner.from_path(priv_key_path)
    verifier = ECKeyVerifier.from_path(pub_key_path)

    bdl = signer.sign(stmnt)
    verifier.verify(bdl)


def test_key_signature_failure(tmp_path: pathlib.Path):
    priv_key_path, pub_key_path = __dump_keys(tmp_path)

    stmnt = __get_stmnt()

    signer = ECKeySigner.from_path(priv_key_path)
    verifier = ECKeyVerifier.from_path(pub_key_path)

    bdl = signer.sign(stmnt)
    bdl.dsse_envelope.signatures[0].sig += b"modified"

    with pytest.raises(VerificationError):
        verifier.verify(bdl)


def test_key_signature_wrong_key(tmp_path: pathlib.Path):
    priv_key_path, _ = __dump_keys(tmp_path)

    stmnt = __get_stmnt()

    signer = ECKeySigner.from_path(priv_key_path)
    verifier = ECKeyVerifier(_PUB_KEY_2)

    bdl = signer.sign(stmnt)

    with pytest.raises(VerificationError):
        verifier.verify(bdl)
