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
from pathlib import Path
import sys
import tempfile

# type: ignore
import atheris
from cryptography.hazmat.primitives import serialization
from utils import _build_hashing_config_from_fdp
from utils import any_files
from utils import create_fuzz_files

import model_signing


def TestOneInput(data: bytes) -> None:
    """Fuzzer on OSS-Fuzz: sign with a random key that parses as private."""
    fdp = atheris.FuzzedDataProvider(data)

    # Generate a random (possibly invalid) private key blob.
    key_size = fdp.ConsumeIntInRange(0, 8 * 1024)
    key_bytes = fdp.ConsumeBytes(key_size)
    try:
        serialization.load_pem_private_key(
            key_bytes, password=None, unsafe_skip_rsa_key_validation=True
        )
    except ValueError:
        return

    # Separate dirs: model tree vs. signature destination.
    with (
        tempfile.TemporaryDirectory(prefix="mt_sign_only_") as tmpdir,
        tempfile.TemporaryDirectory(prefix="mt_sig_fuzz_") as sigdir,
    ):
        root = Path(tmpdir)

        # Create 0..30 files with fuzzed paths and contents.
        create_fuzz_files(root, fdp)

        # Early return if there are NO files.
        if not any_files(root):
            return

        # Persist the parsed private key.
        key_path = os.path.join(tmpdir, "fuzz.priv")
        with open(key_path, "wb") as f:
            f.write(key_bytes)

        # Sign the directory root; signature goes elsewhere.
        model_path = str(root)
        sig_path = os.path.join(sigdir, "model.sig")

        hcfg = _build_hashing_config_from_fdp(fdp)

        scfg = model_signing.signing.Config()
        scfg.set_hashing_config(hcfg)
        signer = scfg.use_elliptic_key_signer(private_key=key_path)
        _ = signer.sign(model_path, sig_path)


def main() -> None:
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
