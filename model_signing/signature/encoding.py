from google.protobuf import json_format
from in_toto_attestation.v1 import statement_pb2 as statement_pb

PAYLOAD_TYPE = "application/vnd.in-toto+json"


def pae(statement: statement_pb.Statement) -> bytes:
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
    pae = ('DSSEV1'
           f' {len(PAYLOAD_TYPE)} {PAYLOAD_TYPE}'
           f' {payload_len} {enc_payload}')
    pae = pae.encode()
    return pae
