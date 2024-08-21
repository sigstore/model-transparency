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

"""This script can be used to verify model signatures."""

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
from model_signing.signature import verifying
from model_signing.signing import in_toto_signature


log = logging.getLogger(__name__)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser("Script to verify models")
    parser.add_argument(
        "--sig_path",
        help="the path to the signature",
        required=True,
        type=pathlib.Path,
        dest="sig_path",
    )
    parser.add_argument(
        "--model_path",
        help="the path to the model's base folder",
        type=pathlib.Path,
        dest="model_path",
    )

    method_cmd = parser.add_subparsers(
        required=True,
        dest="method",
        help="method to verify the model: [pki, private-key, skip]",
    )
    # pki subcommand
    pki = method_cmd.add_parser("pki")
    pki.add_argument(
        "--root_certs",
        help="paths to PEM encoded certificate files or a single file"
        + "used as the root of trust",
        required=False,
        type=list[str],
        default=[],
        dest="root_certs",
    )
    # private key subcommand
    p_key = method_cmd.add_parser("private-key")
    p_key.add_argument(
        "--public_key",
        help="the path to the public key used for verification",
        required=True,
        type=pathlib.Path,
        dest="key",
    )

    method_cmd.add_parser("skip")

    return parser.parse_args()


def _check_private_key_flags(args: argparse.Namespace):
    if args.key == "":
        log.error("--public_key must be defined")
        exit()


def _check_pki_flags(args: argparse.Namespace):
    if not args.root_certs:
        log.warning("no root of trust is set using system default")


def main():
    logging.basicConfig(level=logging.INFO)
    args = _arguments()

    verifier: verifying.Verifier
    log.info(f"Creating verifier for {args.method}")
    if args.method == "private-key":
        _check_private_key_flags(args)
        verifier = key.ECKeyVerifier.from_path(args.key)
    elif args.method == "pki":
        _check_pki_flags(args)
        verifier = pki.PKIVerifier.from_paths(args.root_certs)
    elif args.method == "skip":
        verifier = fake.FakeVerifier()
    else:
        log.error(f"unsupported verification method {args.method}")
        log.error('supported methods: ["pki", "private-key", "skip"]')
        exit(-1)

    log.info(f"Verifying model signature from {args.sig_path}")

    sig = in_toto_signature.IntotoSignature.read(args.sig_path)

    def hasher_factory(file_path: pathlib.Path) -> file.FileHasher:
        return file.SimpleFileHasher(
            file=file_path, content_hasher=memory.SHA256()
        )

    serializer = serialize_by_file.ManifestSerializer(
        file_hasher_factory=hasher_factory
    )

    intoto_verifier = in_toto_signature.IntotoVerifier(verifier)

    try:
        model.verify(
            sig=sig,
            verifier=intoto_verifier,
            model_path=args.model_path,
            serializer=serializer,
            ignore_paths=[args.sig_path],
        )
    except verifying.VerificationError as err:
        log.error(f"verification failed: {err}")

    log.info("all checks passed")


if __name__ == "__main__":
    main()
