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

"""Tests for hashing models through cloud filesystem paths."""

from collections.abc import Iterator
import pathlib

from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from etils import epath
from fsspec.implementations.memory import MemoryFileSystem
import pytest

from model_signing import _cli
from model_signing import _filesystem
from model_signing import hashing
from model_signing import signing
from model_signing import verifying


class _FakeGcsFileSystem(MemoryFileSystem):
    """An in-memory fsspec filesystem accepting gs:// paths."""

    protocol = "gs"


@pytest.fixture
def fake_gcs(monkeypatch: pytest.MonkeyPatch) -> Iterator[_FakeGcsFileSystem]:
    """Routes etils GCS operations to an isolated memory filesystem."""
    filesystem = _FakeGcsFileSystem()
    filesystem.store.clear()
    filesystem.pseudo_dirs[:] = [""]
    monkeypatch.setattr(epath.gpath, "_is_tf_installed", lambda: False)
    monkeypatch.setattr(
        epath.backend.fsspec_backend, "_get_filesystem", lambda _: filesystem
    )
    yield filesystem
    filesystem.store.clear()
    filesystem.pseudo_dirs[:] = [""]


def _populate_remote_model(filesystem: _FakeGcsFileSystem) -> None:
    filesystem.makedirs("gs://bucket/model/nested")
    filesystem.pipe("gs://bucket/model/weights.bin", b"0123456789")
    filesystem.pipe("gs://bucket/model/nested/config.json", b'{"v": 1}')


def _populate_local_model(model: pathlib.Path) -> None:
    (model / "nested").mkdir(parents=True)
    (model / "weights.bin").write_bytes(b"0123456789")
    (model / "nested/config.json").write_bytes(b'{"v": 1}')


@pytest.mark.parametrize(
    "config",
    [
        hashing.Config().use_file_serialization(chunk_size=3),
        hashing.Config().use_file_serialization(hashing_algorithm="blake3"),
        hashing.Config().use_shard_serialization(
            chunk_size=2, shard_size=4, max_workers=1
        ),
    ],
)
def test_remote_hash_matches_local(
    config: hashing.Config, fake_gcs: _FakeGcsFileSystem, tmp_path: pathlib.Path
) -> None:
    """Cloud and local paths produce the same canonical manifest."""
    _populate_remote_model(fake_gcs)
    local_model = tmp_path / "model"
    _populate_local_model(local_model)

    remote_manifest = config.hash("gs://bucket/model")
    local_manifest = config.hash(local_model)

    assert remote_manifest == local_manifest
    assert remote_manifest.model_name == local_manifest.model_name == "model"
    assert (
        remote_manifest.serialization_type == local_manifest.serialization_type
    )


def test_remote_streaming_reads_are_bounded(
    fake_gcs: _FakeGcsFileSystem, monkeypatch: pytest.MonkeyPatch
) -> None:
    """File hashing requests bounded chunks instead of an unbounded read."""
    _populate_remote_model(fake_gcs)
    requested_sizes = []
    original_open = fake_gcs.open

    class _RecordingReader:
        def __init__(self, wrapped):
            self._wrapped = wrapped

        def __enter__(self):
            self._wrapped.__enter__()
            return self

        def __exit__(self, *args):
            return self._wrapped.__exit__(*args)

        def __getattr__(self, name):
            return getattr(self._wrapped, name)

        def read(self, size=-1):
            requested_sizes.append(size)
            return self._wrapped.read(size)

    def recording_open(path, mode="rb", **kwargs):
        opened = original_open(path, mode=mode, **kwargs)
        if "r" in mode:
            return _RecordingReader(opened)
        return opened

    monkeypatch.setattr(fake_gcs, "open", recording_open)

    hashing.Config().use_file_serialization(chunk_size=3, max_workers=1).hash(
        "gs://bucket/model"
    )

    assert requested_sizes
    assert -1 not in requested_sizes
    assert max(requested_sizes) == 3


def test_remote_ignore_paths_are_model_relative(
    fake_gcs: _FakeGcsFileSystem,
) -> None:
    """Remote ignore paths stay within the model and omit matching files."""
    _populate_remote_model(fake_gcs)
    ignore_paths = _cli._resolve_ignore_paths(
        "gs://bucket/model",
        ["nested/config.json", "gs://another-bucket/outside"],
    )

    manifest = (
        hashing.Config()
        .set_ignored_paths(paths=ignore_paths, ignore_git_paths=False)
        .hash("gs://bucket/model")
    )

    assert [str(path) for path in ignore_paths] == ["nested/config.json"]
    assert [
        descriptor.identifier for descriptor in manifest.resource_descriptors()
    ] == ["weights.bin"]


def test_sign_and_verify_remote_model(
    fake_gcs: _FakeGcsFileSystem, tmp_path: pathlib.Path
) -> None:
    """Signing and verification accept the same remote model URI."""
    _populate_remote_model(fake_gcs)
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_key_path = tmp_path / "key.pem"
    public_key_path = tmp_path / "key.pub"
    signature_path = tmp_path / "model.sig"
    private_key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_key_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    signing.Config().use_elliptic_key_signer(private_key=private_key_path).sign(
        "gs://bucket/model", signature_path
    )

    verifier = verifying.Config().use_elliptic_key_verifier(
        public_key=public_key_path
    )
    verifier.verify("gs://bucket/model", signature_path)

    fake_gcs.pipe("gs://bucket/model/unsigned.txt", b"not signed")
    verifier.set_ignore_unsigned_files(True).verify(
        "gs://bucket/model", signature_path
    )

    fake_gcs.pipe("gs://bucket/model/weights.bin", b"tampered")
    with pytest.raises(ValueError, match="Signature mismatch"):
        verifier.verify("gs://bucket/model", signature_path)


def test_digest_cli_preserves_remote_uri(fake_gcs: _FakeGcsFileSystem) -> None:
    """The CLI does not collapse the double slash in a cloud URI."""
    _populate_remote_model(fake_gcs)
    result = CliRunner().invoke(_cli.main, ["digest", "gs://bucket/model"])

    assert result.exit_code == 0, result.output
    algorithm, digest = result.output.strip().split(":")
    assert algorithm == "sha256"
    assert len(digest) == 64


def test_path_conversion_preserves_local_pathlib() -> None:
    """Existing pathlib objects retain their exact local path behavior."""
    local_path = pathlib.Path("model")

    assert _filesystem.as_path(local_path) is local_path
    assert str(_filesystem.as_path("gs://bucket/model")) == "gs://bucket/model"
