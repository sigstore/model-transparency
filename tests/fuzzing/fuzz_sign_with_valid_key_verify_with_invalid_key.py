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
import shutil
import sys
import tempfile

# type: ignore
import atheris
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import model_signing


_KEYDIR: str = tempfile.mkdtemp(prefix="mt_valid_key_")


def _cleanup_keys() -> None:
    shutil.rmtree(_KEYDIR, ignore_errors=True)


atexit.register(_cleanup_keys)

_PRIV_PATH: str = os.path.join(_KEYDIR, "signer.priv")
_PUB_PATH: str = os.path.join(_KEYDIR, "signer.pub")

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


def TestOneInput(data):
    """Fuzzer running on OSS-Fuzz.

    Generate random public-key bytes and ensure they parse
    with the PEM loader; if they do, sign a model and verify
    using a file containing those bytes.
    """
    fdp = atheris.FuzzedDataProvider(data)

    pubkey_size = fdp.ConsumeIntInRange(0, 8 * 1024)
    pubkey_bytes = fdp.ConsumeBytes(pubkey_size)
    try:
        serialization.load_pem_public_key(pubkey_bytes)
    except ValueError:
        return

    with tempfile.TemporaryDirectory(prefix="mt_verify_bytes_") as tmpdir:
        model_path = os.path.join(tmpdir, "model.bin")
        model_size = fdp.ConsumeIntInRange(0, 64 * 1024)
        with open(model_path, "wb") as f:
            f.write(fdp.ConsumeBytes(model_size))

        sig_path = os.path.join(tmpdir, "model.sig")

        scfg = model_signing.signing.Config()
        signer = scfg.use_elliptic_key_signer(private_key=_PRIV_PATH)
        _ = signer.sign(model_path, sig_path)

        pubkey_path = os.path.join(tmpdir, "fuzz.pub")
        with open(pubkey_path, "wb") as f:
            f.write(pubkey_bytes)

        vcfg = model_signing.verifying.Config()
        verifier = vcfg.use_elliptic_key_verifier(public_key=pubkey_path)
        verifier.verify(model_path, sig_path)


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
