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

import os
import sys
import tempfile

# type: ignore
import atheris
from cryptography.hazmat.primitives import serialization

import model_signing


def TestOneInput(data):
    """Fuzzer running on OSS-Fuzz.

    Create a random model and key file,
    then sign with the random key file.
    Parse the key early to ignore if invalid.
    """
    fdp = atheris.FuzzedDataProvider(data)

    pubkey_size = fdp.ConsumeIntInRange(0, 8 * 1024)
    key_bytes = fdp.ConsumeBytes(pubkey_size)
    try:
        serialization.load_pem_private_key(
            key_bytes, password=None, unsafe_skip_rsa_key_validation=True
        )
    except ValueError as e:
        print(e)
        return

    with tempfile.TemporaryDirectory(prefix="mt_sign_only_") as tmpdir:
        model_path = os.path.join(tmpdir, "model.bin")
        model_size = fdp.ConsumeIntInRange(0, 64 * 1024)
        with open(model_path, "wb") as f:
            f.write(fdp.ConsumeBytes(model_size))

        key_path = os.path.join(tmpdir, "fuzz.priv")
        with open(key_path, "wb") as f:
            f.write(key_bytes)

        sig_path = os.path.join(tmpdir, "model.sig")

        scfg = model_signing.signing.Config()
        signer = scfg.use_elliptic_key_signer(private_key=key_path)
        _ = signer.sign(model_path, sig_path)


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
