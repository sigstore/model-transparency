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
import collections

from model_signing import model
from model_signing.hashing import file
from model_signing.hashing import state
from model_signing.hashing import memory
from model_signing.serialization import serialize_by_file
from model_signing.serialization import serialize_by_state
from model_signing.signature import fake
from model_signing.signature import key
from model_signing.signature import pki
from model_signing.signing import in_toto
from model_signing.signing import in_toto_signature
from model_signing.signing import signing
from model_signing.signing import sigstore
import torch
import torch.nn as nn
import torch.nn.functional as F


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
        help="method to sign the model: [pki, private-key, sigstore, skip]",
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
    # sigstore
    sigstore = method_cmd.add_parser("sigstore")
    sigstore.add_argument(
        "--use_ambient_credentials",
        help="use ambient credentials (also known as Workload Identity,"
        + "default is true)",
        required=False,
        type=bool,
        default=True,
        dest="use_ambient_credentials",
    )
    sigstore.add_argument(
        "--staging",
        help="Use Sigstore's staging instances, instead of the default"
        " production instances",
        action="store_true",
        dest="sigstore_staging",
    )
    sigstore.add_argument(
        "--identity-token",
        help="the OIDC identity token to use",
        required=False,
        dest="identity_token",
    )
    # skip
    method_cmd.add_parser("skip")

    return parser.parse_args()


def _get_payload_signer(args: argparse.Namespace) -> signing.Signer:
    if args.method == "private-key":
        _check_private_key_options(args)
        payload_signer = key.ECKeySigner.from_path(
            private_key_path=args.key_path
        )
        return in_toto_signature.IntotoSigner(payload_signer)
    elif args.method == "pki":
        _check_pki_options(args)
        payload_signer = pki.PKISigner.from_path(
            args.key_path, args.signing_cert_path, args.cert_chain_path
        )
        return in_toto_signature.IntotoSigner(payload_signer)
    elif args.method == "sigstore":
        return sigstore.SigstoreDSSESigner(
            use_ambient_credentials=args.use_ambient_credentials,
            use_staging=args.sigstore_staging,
            identity_token=args.identity_token,
        )
    elif args.method == "skip":
        return in_toto_signature.IntotoSigner(fake.FakeSigner())
    else:
        log.error(f"unsupported signing method {args.method}")
        log.error(
            'supported methods: ["pki", "private-key", "sigstore", "skip"]'
        )
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


def sign_files():
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

    sig = model.sign_file(
        model_path=args.model_path,
        signer=payload_signer,
        payload_generator=in_toto.DigestsIntotoPayload.from_manifest,
        serializer=serializer,
        ignore_paths=[args.sig_out],
    )

    log.info(f'Storing signature at "{args.sig_out}"')
    sig.write(args.sig_out)


def sign_model():
    logging.basicConfig(level=logging.INFO)
    args = _arguments()

    log.info(f"Creating signer for {args.method}")
    payload_signer = _get_payload_signer(args)
    
    class Net(nn.Module):
        def __init__(self):
            super().__init__()
            self.conv1 = nn.Conv2d(3, 6, 5)
            self.pool = nn.MaxPool2d(2, 2)
            self.conv2 = nn.Conv2d(6, 16, 5)
            self.fc1 = nn.Linear(16 * 5 * 5, 120)
            self.fc2 = nn.Linear(120, 84)
            self.fc3 = nn.Linear(84, 10)

        def forward(self, x):
            x = self.pool(F.relu(self.conv1(x)))
            x = self.pool(F.relu(self.conv2(x)))
            x = torch.flatten(x, 1) # flatten all dimensions except batch
            x = F.relu(self.fc1(x))
            x = F.relu(self.fc2(x))
            x = self.fc3(x)
            return x
    net = Net().to('cuda')

    def hasher_factory(state_dict: collections.OrderedDict) -> state.StateHasher:
        return state.SimpleStateHasher(
            state=state_dict, content_hasher=memory.SHA256()
        )

    serializer = serialize_by_state.ManifestSerializer(
        state_hasher_factory=hasher_factory
    )

    states = [net.state_dict(),]

    sig = model.sign_state(
        states=states,
        signer=payload_signer,
        payload_generator=in_toto.DigestsIntotoPayload.from_manifest,
        serializer=serializer,
    )

    log.info(f'Storing signature at "{args.sig_out}"')
    sig.write(args.sig_out)


if __name__ == "__main__":
    sign_model()
