# Copyright (c) 2024, NVIDIA CORPORATION.  All rights reserved.
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

"""Script to sign models."""

import argparse
import logging
import pathlib

from model_signing import model
from model_signing.hashing import file
from model_signing.hashing import memory
from model_signing.serialization import serialize_by_file
from model_signing.signature import fake
from model_signing.signature import key
from model_signing.signature import pki
from model_signing.signature import signing
from model_signing.signing import in_toto
from model_signing.signing import in_toto_signature


log = logging.getLogger(__name__)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser("Script to sign models")
    parser.add_argument(
        "--model_path",
        help="path to the model to sign",
        required=True,
        type=pathlib.Path,
        dest="model_path",
    )
    parser.add_argument(
        "--sig_out",
        help="the output file, it defaults ./model.sig",
        required=False,
        type=pathlib.Path,
        default=pathlib.Path("./model.sig"),
        dest="sig_out",
    )

    method_cmd = parser.add_subparsers(
        required=True,
        dest="method",
        help="method to sign the model: [pki, private-key, skip]",
    )
    # PKI
    pki = method_cmd.add_parser("pki")
    pki.add_argument(
        "--cert_chain",
        help="paths to pem encoded certificate files or a single file"
        + "containing a chain",
        required=False,
        type=list[str],
        default=[],
        nargs="+",
        dest="cert_chain_path",
    )
    pki.add_argument(
        "--signing_cert",
        help="the pem encoded signing cert",
        required=True,
        type=pathlib.Path,
        dest="signing_cert_path",
    )
    pki.add_argument(
        "--private_key",
        help="the path to the private key PEM file",
        required=True,
        type=pathlib.Path,
        dest="key_path",
    )
    # private key
    p_key = method_cmd.add_parser("private-key")
    p_key.add_argument(
        "--private_key",
        help="the path to the private key PEM file",
        required=True,
        type=pathlib.Path,
        dest="key_path",
    )
    # skip
    method_cmd.add_parser("skip")

    return parser.parse_args()


def _get_payload_signer(args: argparse.Namespace) -> signing.Signer:
    if args.method == "private-key":
        _check_private_key_options(args)
        return key.ECKeySigner.from_path(private_key_path=args.key_path)
    elif args.method == "pki":
        _check_pki_options(args)
        return pki.PKISigner.from_path(
            args.key_path, args.signing_cert_path, args.cert_chain_path
        )
    elif args.method == "skip":
        return fake.FakeSigner()
    else:
        log.error(f"unsupported signing method {args.method}")
        log.error('supported methods: ["pki", "private-key", "skip"]')
        exit(-1)


def _check_private_key_options(args: argparse.Namespace):
    if args.key_path == "":
        log.error("--private_key must be set to a valid private key PEM file")
        exit()


def _check_pki_options(args: argparse.Namespace):
    _check_private_key_options(args)
    if args.signing_cert_path == "":
        log.error(
            (
                "--signing_cert must be set to a valid ",
                "PEM encoded signing certificate",
            )
        )
        exit()
    if args.cert_chain_path == "":
        log.warning("No certificate chain provided")


def main():
    logging.basicConfig(level=logging.INFO)
    args = _arguments()

    log.info(f"Creating signer for {args.method}")
    payload_signer = _get_payload_signer(args)
    log.info(f"Signing model at {args.model_path}")

    def hasher_factory(file_path: pathlib.Path) -> file.FileHasher:
        return file.SimpleFileHasher(
            file=file_path, content_hasher=memory.SHA256()
        )

    serializer = serialize_by_file.ManifestSerializer(
        file_hasher_factory=hasher_factory
    )

    intoto_signer = in_toto_signature.IntotoSigner(payload_signer)
    sig = model.sign(
        model_path=args.model_path,
        signer=intoto_signer,
        payload_generator=in_toto.DigestsIntotoPayload.from_manifest,
        serializer=serializer,
        ignore_paths=[args.sig_out],
    )

    log.info(f'Storing signature at "{args.sig_out}"')
    sig.write(args.sig_out)


if __name__ == "__main__":
    main()
