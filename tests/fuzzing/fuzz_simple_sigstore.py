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

import importlib
import os
from pathlib import Path
import sys
import tempfile

# type: ignore
import atheris
from sigstore.models import TrustedRoot
from utils import _build_hashing_config_from_fdp
from utils import any_files
from utils import create_fuzz_files

from model_signing import signing
from model_signing import verifying


def _patch_sigstore_get_dirs(metadata_dir: Path, artifacts_dir: Path) -> None:
    """Overwrite sigstore._internal.tuf._get_dirs(url: str).

    This allows us to return directories that the fuzzer controls.
    """
    tuf_mod = importlib.import_module("sigstore._internal.tuf")

    def _stub_get_dirs(url: str):
        return metadata_dir, artifacts_dir

    tuf_mod._get_dirs = _stub_get_dirs


def _patch_trust_updater_offline_default_true() -> None:
    """Make TrustUpdater.__init__ offline by default.

    This avoids network calls at runtime which is important
    for when the fuzzer runs on OSS-Fuzz.
    """
    tuf_mod = importlib.import_module("sigstore._internal.tuf")
    trust_updater = tuf_mod.TrustUpdater
    _orig_init = trust_updater.__init__

    def _patched_init(self, url: str, offline: bool = True) -> None:
        _orig_init(self, url, offline=True)

    trust_updater.__init__ = _patched_init


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    # When the fuzzer creates a signer further down,
    # Sigstore will use a trusted root that the fuzzer
    # has created. It is possible for the fuzzer to create
    # an invalid trusted root, so it creates and tests it
    # here - very early in the whole iteration - to return
    # if it is invalid. If it is valid, it will use it laeter.
    root_sz = fdp.ConsumeIntInRange(0, 16 * 1024)  # up to 16KB
    trusted_root_bytes = fdp.ConsumeBytes(root_sz)

    tmp_tr_path: Path
    with tempfile.NamedTemporaryFile(
        prefix="trusted_root_", suffix=".json", delete=False
    ) as tmp_tr:
        tmp_tr_path = Path(tmp_tr.name)
        tmp_tr.write(trusted_root_bytes)

    try:
        # Early validation to catch bad JSON
        TrustedRoot.from_file(str(tmp_tr_path))
    except Exception:
        # Bad or unsupported JSON: return and retry
        os.unlink(tmp_tr_path)
        return

    # Temp dirs for sigstore TUF (metadata/artifacts) + model + signature
    with (
        tempfile.TemporaryDirectory(prefix="tuf-metadata-") as md_tmp,
        tempfile.TemporaryDirectory(prefix="tuf-artifacts-") as art_tmp,
        tempfile.TemporaryDirectory(prefix="mt_file_fuzz_") as tmpdir,
        tempfile.TemporaryDirectory(prefix="mt_sig_fuzz_") as sigdir,
    ):
        # Create the model root
        root = Path(tmpdir)

        # 1) Populate model dir with randomizd files and exit early if empty
        create_fuzz_files(root, fdp)
        if not any_files(root):
            return

        metadata_dir = Path(md_tmp)
        artifacts_dir = Path(art_tmp)

        # 2) Create the hooks into sigstore python
        _patch_sigstore_get_dirs(metadata_dir, artifacts_dir)
        _patch_trust_updater_offline_default_true()

        # 3) Write the (already validated) trusted_root.json into artifacts dir
        trusted_root_path = artifacts_dir / "trusted_root.json"
        trusted_root_path.write_bytes(trusted_root_bytes)

        # 4) Fuzz/write signing_config.v0.2.json
        signing_config_path = artifacts_dir / "signing_config.v0.2.json"
        cfg_sz = fdp.ConsumeIntInRange(0, 16 * 1024)  # up to 16KB
        signing_config_path.write_bytes(fdp.ConsumeBytes(cfg_sz))

        # 5) Prepare signature path
        signature_path = Path(sigdir) / "model.signature"

        # 6) Sign
        expected_identity = (
            fdp.ConsumeBytes(32).decode("utf-8", errors="ignore")
            or "default-identity"
        )
        expected_oidc_issuer = (
            fdp.ConsumeBytes(32).decode("utf-8", errors="ignore")
            or "https://example.com/"
        )
        sigstore_oidc_beacon_token = (
            fdp.ConsumeBytes(64).decode("utf-8", errors="ignore") or "token"
        )

        hcfg = _build_hashing_config_from_fdp(fdp)

        sc = signing.Config()
        sc.set_hashing_config(hcfg)
        sc.use_sigstore_signer(
            use_staging=True, identity_token=sigstore_oidc_beacon_token
        )
        sc.sign(root, signature_path)

        if not signature_path.exists():
            return

        # 7) Verify
        vc = verifying.Config()
        vc.set_hashing_config(hcfg)
        vc.use_sigstore_verifier(
            identity=expected_identity,
            oidc_issuer=expected_oidc_issuer,
            use_staging=True,
        )
        vc.verify(root, signature_path)


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
