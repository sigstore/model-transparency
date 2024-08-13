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
from google.protobuf import json_format
from in_toto_attestation.v1 import statement_pb2 as statement_pb


PAYLOAD_TYPE = "application/vnd.in-toto+json"


def pae(
    statement: statement_pb.Statement,  # pylint: disable=no-member
) -> bytes:
    """Generates the PAE encoding of the statement.

    See https://github.com/secure-systems-lab/dsse/blob/v1.0.0/protocol.md
    for details.

    Args:
        statement (statement_pb.Statement): the statement to be encoded.

    Returns:
        bytes: the encoded statement as bytes.
    """
    enc_payload = json_format.MessageToJson(statement).encode()
    payload_len = len(enc_payload)
    pae = (
        "DSSEV1"
        f" {len(PAYLOAD_TYPE)} {PAYLOAD_TYPE}"
        f" {payload_len} {enc_payload}"
    )
    pae = pae.encode()
    return pae
