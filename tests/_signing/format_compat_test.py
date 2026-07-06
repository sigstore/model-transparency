# Copyright 2026 The Sigstore Authors
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

"""Tests for backward compatible signature format support."""

import json
import warnings

from model_signing._signing import signing


class TestSignatureFormat:
    """Tests for SignatureFormat enum and format detection."""

    def test_sig_extension_is_legacy(self):
        import pathlib

        fmt = signing.detect_signature_format(pathlib.Path("model.sig"))
        assert fmt == signing.SignatureFormat.LEGACY_SINGLE_JSON

    def test_jsonl_extension_is_jsonl(self):
        import pathlib

        fmt = signing.detect_signature_format(pathlib.Path("claims.jsonl"))
        assert fmt == signing.SignatureFormat.JSONL

    def test_other_extension_is_jsonl(self):
        import pathlib

        fmt = signing.detect_signature_format(pathlib.Path("model.bundle"))
        assert fmt == signing.SignatureFormat.JSONL

    def test_output_format_matches_detect(self):
        import pathlib

        for name, expected in [
            ("model.sig", signing.SignatureFormat.LEGACY_SINGLE_JSON),
            ("claims.jsonl", signing.SignatureFormat.JSONL),
            ("model.bundle", signing.SignatureFormat.JSONL),
        ]:
            path = pathlib.Path(name)
            assert signing.detect_output_format(path) == expected
            assert signing.detect_signature_format(path) == expected


class TestDeprecationWarnings:
    """Tests that deprecation warnings are emitted for .sig format."""

    def test_write_sig_emits_deprecation(self, tmp_path):
        """Writing to a .sig file should emit a deprecation warning."""
        from model_signing._signing import sign_sigstore as sigstore

        # Create a minimal mock bundle
        from unittest import mock

        bundle = mock.MagicMock()
        bundle.to_json.return_value = json.dumps({"test": "bundle"})

        sig = sigstore.Signature(bundle)
        sig_path = tmp_path / "model.sig"

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            sig.write(sig_path)

        deprecation_warnings = [
            x for x in w if issubclass(x.category, DeprecationWarning)
        ]
        assert len(deprecation_warnings) == 1
        assert ".sig format" in str(deprecation_warnings[0].message)

    def test_write_jsonl_no_deprecation(self, tmp_path):
        """Writing to a .jsonl file should not emit a deprecation warning."""
        from model_signing._signing import sign_sigstore as sigstore

        from unittest import mock

        bundle = mock.MagicMock()
        bundle.to_json.return_value = json.dumps({"test": "bundle"})

        sig = sigstore.Signature(bundle)
        sig_path = tmp_path / "claims.jsonl"

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            sig.write(sig_path)

        deprecation_warnings = [
            x for x in w if issubclass(x.category, DeprecationWarning)
        ]
        assert len(deprecation_warnings) == 0

    def test_read_sig_emits_deprecation(self, tmp_path):
        """Reading from a .sig file should emit a deprecation warning."""
        from model_signing._signing import sign_sigstore as sigstore
        from sigstore import models as sigstore_models
        from unittest import mock

        sig_path = tmp_path / "model.sig"
        sig_path.write_text(json.dumps({"test": "bundle"}))

        with (
            mock.patch.object(
                sigstore_models.Bundle,
                "from_json",
                return_value=mock.MagicMock(),
            ),
            warnings.catch_warnings(record=True) as w,
        ):
            warnings.simplefilter("always")
            sigstore.Signature.read(sig_path)

        deprecation_warnings = [
            x for x in w if issubclass(x.category, DeprecationWarning)
        ]
        assert len(deprecation_warnings) == 1

    def test_jsonl_append_behavior(self, tmp_path):
        """Writing multiple signatures to JSONL should append."""
        from model_signing._signing import sign_sigstore as sigstore
        from unittest import mock

        bundle1 = mock.MagicMock()
        bundle1.to_json.return_value = json.dumps({"claim": 1})
        bundle2 = mock.MagicMock()
        bundle2.to_json.return_value = json.dumps({"claim": 2})

        sig_path = tmp_path / "claims.jsonl"

        sigstore.Signature(bundle1).write(sig_path)
        sigstore.Signature(bundle2).write(sig_path)

        lines = [
            l for l in sig_path.read_text().splitlines() if l.strip()
        ]
        assert len(lines) == 2
        assert json.loads(lines[0]) == {"claim": 1}
        assert json.loads(lines[1]) == {"claim": 2}
