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

from sigstore_protobuf_specs.dev.sigstore.bundle import v1 as bundle_pb

from model_signing import model
from model_signing.hashing import file
from model_signing.hashing import memory
from model_signing.serialization import serialize_by_file
from model_signing.signature import SUPPORTED_METHODS
from model_signing.signature import verifying
from model_signing.signature import key
from model_signing.signature import pki
from model_signing.signature import sigstore
from model_signing.signature import fake
from model_signing.signing import in_toto

log = logging.getLogger(__name__)


def __arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser('Script to verify models')
    parser.add_argument(
        '--sig_path',
        help='the path to the signature',
        required=True,
        type=pathlib.Path,
        dest='sig_path')
    parser.add_argument(
        '--model_path',
        help='the path to the model\'s base folder',
        type=pathlib.Path,
        dest='model_path')

    method_cmd = parser.add_subparsers(required=True, dest='method')
    # sigstore subcommand
    sigstore = method_cmd.add_parser('sigstore')
    sigstore.add_argument(
        '--id_provider',
        help='URL to the ID provider',
        required=True,
        type=str,
        dest='id_provider')
    sigstore.add_argument(
        '--id',
        help='the identity that is expected to have signed the model',
        required=True,
        type=str,
        dest='id')
    # pki subcommand
    pki = method_cmd.add_parser('pki')
    pki.add_argument(
        '--root_certs',
        help=('paths to PEM encoded certificate files or a single file ',
              'used as the root of trust'),
        required=False,
        type=list[str],
        default=[],
        dest='root_certs'
    )
    # private key subcommand
    pKey = method_cmd.add_parser('private-key')
    pKey.add_argument(
        '--public_key',
        help='the path to the public key used for verification',
        required=True,
        type=pathlib.Path,
        dest='key')

    method_cmd.add_parser('skip')

    return parser.parse_args()


def __check_sigstore_flags(args: argparse.Namespace):
    if args.id == '' or args.id_provider == '':
        log.error(
            '--id_provider and --id are required for sigstore verification')
        exit()


def __check_private_key_flags(args: argparse.Namespace):
    if args.key == '':
        log.error('--public_key must be defined')
        exit()


def __check_pki_flags(args: argparse.Namespace):
    if not args.root_certs:
        log.warning('no root of trust is set using system default')


def main():
    logging.basicConfig(level=logging.INFO)
    args = __arguments()

    verifier: verifying.Verifier
    log.info(f'Creating verifier for {args.method}')
    if args.method == 'sigstore':
        __check_sigstore_flags(args)
        verifier = sigstore.SigstoreVerifier(
            args.id_provider, args.id)
    elif args.method == 'private-key':
        __check_private_key_flags(args)
        verifier = key.ECKeyVerifier.from_path(
            args.key)
    elif args.method == 'pki':
        __check_pki_flags(args)
        verifier = pki.PKIVerifier.from_paths(
            args.root_certs)
    elif args.method == 'skip':
        verifier = fake.FakeVerifier()
    else:
        log.error(f'unsupported verification method {args.method}')
        log.error(f'supported methods: {SUPPORTED_METHODS}')
        exit()

    log.info(f'Verifying model signature from {args.sig_path}')

    sig = in_toto.IntotoSignature.read(args.sig_path)

    def hasher_factory(file_path: pathlib.Path) -> file.FileHasher:
        return file.SimpleFileHasher(
            file=file_path,
            content_hasher=memory.SHA256(),
        )

    serializer = serialize_by_file.ManifestSerializer(
        file_hasher_factory=hasher_factory)

    intoto_verifier = in_toto.IntotoVerifier(verifier)

    try:
        model.verify(
            sig=sig,
            verifier=intoto_verifier,
            model_path=args.model_path,
            serializer=serializer,
            ignore_paths=[args.sig_path])
    except verifying.VerificationError as err:
        log.error(f'verification failed: {err}')

    log.info('all checks passed')


if __name__ == '__main__':
    main()
