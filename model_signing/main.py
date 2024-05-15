# Copyright 2024 The Sigstore Authors
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
# See the License for the specific language governing perepo_managerissions and
# limitations under the License.

import argparse
import sys
from pathlib import Path
import model


# https://github.com/sigstore/sigstore-python/issues/661
# contains the logic to start the web browser.

def readOptions():
    parser = argparse.ArgumentParser("CLI for signing AI models")
    subcommands = parser.add_subparsers(required=True, dest="subcommand")

    # TODO: option for a path to store the signature.
    # Sign group.
    sign = subcommands.add_parser(
        "sign", formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    sign.add_argument("--path", required=True, help="The path to sign")
    sign.add_argument("--disable-ambient", required=False,
                      default=False, action='store_true',
                      help="Auto detect ambient authority")

    # Verify group.
    verify = subcommands.add_parser(
        "verify", formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    verify.add_argument("--path", required=True,
                        help="The path to a file to verify")
    verify.add_argument("--identity", required=True,
                        help="The identity (email, workload identity) to " +
                        "verify")
    verify.add_argument("--identity-provider", required=True,
                        help="The OIDC provider to verify")

    args = parser.parse_args()
    return args


def signature_path(modelfn: Path) -> Path:
    if modelfn.is_file():
        return Path(modelfn.parent).joinpath(f"{modelfn.name}.sig")
    return modelfn.joinpath("model.sig")


def ignored_paths(modelfn: Path) -> [Path]:
    if modelfn.is_file():
        return []
    return [modelfn.joinpath(".git")]


# Sign function
def sign(modelfn: Path, disable_ambient: bool) -> model.SignatureResult:
    signer = model.SigstoreSigner(disable_ambient=disable_ambient)
    return signer.sign(modelfn, signature_path(modelfn),
                       ignored_paths(modelfn))


def verify(modelfn: Path, issuer: str, identity: str,
           offline=False) -> model.VerificationResult:
    verifier = model.SigstoreVerifier(oidc_provider=issuer, identity=identity)
    return verifier.verify(modelfn, signature_path(modelfn),
                           ignored_paths(modelfn), offline)


def main(args) -> int:
    if args.subcommand == "sign":
        result = sign(Path(args.path), disable_ambient=args.disable_ambient)
        if result:
            print("signature success")
        else:
            print(f"signature failure: {str(result)}")
            return -1
    elif args.subcommand == "verify":
        modelfn = Path(args.path)
        result = verify(modelfn=modelfn,
                        issuer=args.identity_provider,
                        identity=args.identity)
        if result:
            print("verification success")
        else:
            print(f"verification failure: {str(result)}")
            return -1
    return 0


if __name__ == '__main__':
    args = readOptions()

    sys.exit(main(args))
