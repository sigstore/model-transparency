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

import atexit
import os
from pathlib import Path
import shutil
import sys
import tempfile

# type: ignore
import atheris
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from utils import _build_hashing_config_from_fdp
from utils import any_files
from utils import create_fuzz_files

import model_signing


_KEYDIR: str = tempfile.mkdtemp(prefix="mt_valid_key_")


def _cleanup_keys() -> None:
    shutil.rmtree(_KEYDIR, ignore_errors=True)


atexit.register(_cleanup_keys)

_PRIV_PATH: str = os.path.join(_KEYDIR, "signer.priv")
_PUB_PATH: str = os.path.join(_KEYDIR, "signer.pub")

# Create a fresh ECDSA keypair once per process (valid signing key).
if not (os.path.exists(_PRIV_PATH) and os.path.exists(_PUB_PATH)):
    priv = ec.generate_private_key(ec.SECP256R1())
    with open(_PRIV_PATH, "wb") as f:
        f.write(
            priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(_PUB_PATH, "wb") as f:
        f.write(
            priv.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


def TestOneInput(data: bytes) -> None:
    """Sign with a valid key; verify with a parseable but mismatched key."""
    fdp = atheris.FuzzedDataProvider(data)

    # Prepare a random (possibly unrelated) public key blob.
    pubkey_size = fdp.ConsumeIntInRange(0, 8 * 1024)
    pubkey_bytes = fdp.ConsumeBytes(pubkey_size)
    try:
        serialization.load_pem_public_key(pubkey_bytes)
    except ValueError:
        return

    # Separate dirs: model tree vs. signature destination.
    with (
        tempfile.TemporaryDirectory(prefix="mt_verify_bytes_") as tmpdir,
        tempfile.TemporaryDirectory(prefix="mt_sig_fuzz_") as sigdir,
    ):
        root = Path(tmpdir)

        # Create 0..30 files with safe, fuzzed paths & contents.
        create_fuzz_files(root, fdp)

        # Early return if the directory is empty (no regular files).
        if not any_files(root):
            return

        model_path = str(root)
        sig_path = os.path.join(sigdir, "model.sig")

        hcfg = _build_hashing_config_from_fdp(fdp)

        # Sign using the valid private key created at module import time.
        scfg = model_signing.signing.Config()
        scfg.set_hashing_config(hcfg)
        signer = scfg.use_elliptic_key_signer(private_key=_PRIV_PATH)
        _ = signer.sign(model_path, sig_path)

        # Write the (parseable but likely mismatched) public key to a file.
        pubkey_path = os.path.join(tmpdir, "fuzz.pub")
        with open(pubkey_path, "wb") as f:
            f.write(pubkey_bytes)

        # Verify with the fuzzed public key.
        vcfg = model_signing.verifying.Config()
        vcfg.set_hashing_config(hcfg)
        try:
            verifier = vcfg.use_elliptic_key_verifier(public_key=pubkey_path)
        except ValueError:
            return  # skip failing on unsupported keys or invalid PEM files
        verifier.verify(model_path, sig_path)


def main() -> None:
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
