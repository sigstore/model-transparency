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


_KEYDIR: str = tempfile.mkdtemp(prefix="mt_keys_pool_")


def _cleanup_keys() -> None:
    shutil.rmtree(_KEYDIR, ignore_errors=True)


atexit.register(_cleanup_keys)


def _write_keypair(
    priv: ec.EllipticCurvePrivateKey, priv_path: str, pub_path: str
) -> None:
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(priv_path, "wb") as f:
        f.write(priv_pem)
    with open(pub_path, "wb") as f:
        f.write(pub_pem)


KEY_SPECS: list[dict[str, str]] = []
for cname, curve in [
    ("p256", ec.SECP256R1()),
    ("p384", ec.SECP384R1()),
    ("p521", ec.SECP521R1()),
]:
    priv = ec.generate_private_key(curve)
    base = os.path.join(_KEYDIR, f"ecdsa-{cname}")
    _write_keypair(priv, base + ".priv", base + ".pub")
    KEY_SPECS.append(
        {"name": f"ecdsa-{cname}", "priv": base + ".priv", "pub": base + ".pub"}
    )


def _pick_key_spec(fdp: atheris.FuzzedDataProvider) -> dict[str, str]:
    return KEY_SPECS[fdp.ConsumeIntInRange(0, len(KEY_SPECS) - 1)]


def TestOneInput(data: bytes) -> None:
    """Fuzzer running on OSS-Fuzz: sign & verify with matching key."""
    fdp = atheris.FuzzedDataProvider(data)

    # One temp dir for the model directory; a separate one for the signature.
    with (
        tempfile.TemporaryDirectory(prefix="mt_file_fuzz_") as tmpdir,
        tempfile.TemporaryDirectory(prefix="mt_sig_fuzz_") as sigdir,
    ):
        root = Path(tmpdir)

        # Create 0..30 files with fuzzed relative paths and contents (safely).
        create_fuzz_files(root, fdp)

        # If there are NO files in root (skip empty directory cases).
        if not any_files(root):
            return

        model_path = str(root)
        sig_path = os.path.join(sigdir, "model.sig")

        key_spec = _pick_key_spec(fdp)

        hcfg = _build_hashing_config_from_fdp(fdp)

        scfg = model_signing.signing.Config()
        scfg.set_hashing_config(hcfg)
        signer = scfg.use_elliptic_key_signer(private_key=key_spec["priv"])
        _ = signer.sign(model_path, sig_path)

        vcfg = model_signing.verifying.Config()
        vcfg.set_hashing_config(hcfg)
        verifier = vcfg.use_elliptic_key_verifier(public_key=key_spec["pub"])
        verifier.verify(model_path, sig_path)


def main() -> None:
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
