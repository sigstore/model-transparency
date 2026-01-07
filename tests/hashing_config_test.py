from model_signing import hashing


def test_set_ignored_paths_relative_to_model(tmp_path, monkeypatch):
    model = tmp_path / "model"
    model.mkdir()
    (model / "ignored.txt").write_text("skip")
    (model / "keep.txt").write_text("keep")

    cfg = hashing.Config().set_ignored_paths(paths=["ignored.txt"])
    # Change working directory to ensure ignored paths aren't resolved against
    # the current directory used at hashing time.
    monkeypatch.chdir(tmp_path)

    manifest = cfg.hash(model)
    identifiers = {rd.identifier for rd in manifest.resource_descriptors()}
    assert "ignored.txt" not in identifiers
    assert "keep.txt" in identifiers


def test_blake3_shard_serialization_equals_file_serialization(tmp_path):
    """Test that blake3 shard produces the same hash as file serialization.

    This is a key property of blake3: because it already operates in parallel,
    the shard serialization API should bypass sharding and produce identical
    results to file serialization.
    """
    model = tmp_path / "model"
    model.mkdir()
    (model / "file1.txt").write_text("some content here")
    (model / "file2.txt").write_text("more content")
    subdir = model / "subdir"
    subdir.mkdir()
    (subdir / "file3.txt").write_text("nested content")

    # Hash with file serialization
    cfg_file = hashing.Config().use_file_serialization(
        hashing_algorithm="blake3"
    )
    manifest_file = cfg_file.hash(model)

    # Hash with shard serialization
    cfg_shard = hashing.Config().use_shard_serialization(
        hashing_algorithm="blake3"
    )
    manifest_shard = cfg_shard.hash(model)

    # The manifests should be equal
    assert manifest_file == manifest_shard


def test_blake3_shard_serialization_with_different_shard_sizes(tmp_path):
    """Test that blake3 produces the same hash regardless of shard_size.

    Since blake3 bypasses sharding, different shard_size parameters should
    not affect the output.
    """
    model = tmp_path / "model"
    model.mkdir()
    # Create a larger file to ensure it would be sharded with other algorithms
    (model / "large.txt").write_text("x" * 10000)

    # Hash with default shard size
    cfg1 = hashing.Config().use_shard_serialization(hashing_algorithm="blake3")
    manifest1 = cfg1.hash(model)

    # Hash with small shard size
    cfg2 = hashing.Config().use_shard_serialization(
        hashing_algorithm="blake3", shard_size=100
    )
    manifest2 = cfg2.hash(model)

    # Hash with large shard size
    cfg3 = hashing.Config().use_shard_serialization(
        hashing_algorithm="blake3", shard_size=1000000
    )
    manifest3 = cfg3.hash(model)

    # All manifests should be equal
    assert manifest1 == manifest2
    assert manifest1 == manifest3


def test_blake3_file_serialization_with_max_workers(tmp_path):
    """Test that blake3 hashes the same with different max_workers settings."""
    model = tmp_path / "model"
    model.mkdir()
    (model / "file1.txt").write_text("content 1")
    (model / "file2.txt").write_text("content 2")

    # Hash with default max_workers
    cfg1 = hashing.Config().use_file_serialization(hashing_algorithm="blake3")
    manifest1 = cfg1.hash(model)

    # Hash with max_workers=1
    cfg2 = hashing.Config().use_file_serialization(
        hashing_algorithm="blake3", max_workers=1
    )
    manifest2 = cfg2.hash(model)

    # Hash with max_workers=4
    cfg3 = hashing.Config().use_file_serialization(
        hashing_algorithm="blake3", max_workers=4
    )
    manifest3 = cfg3.hash(model)

    # All manifests should be equal
    assert manifest1 == manifest2
    assert manifest1 == manifest3


def test_signature_files_always_excluded(tmp_path):
    """Test that signature files are always excluded from hashing."""
    model = tmp_path / "model"
    model.mkdir()
    (model / "model.txt").write_text("model content")
    (model / "model.sig").write_text("signature")
    (model / "backup.sig").write_text("old signature")

    cfg = hashing.Config()
    manifest = cfg.hash(model)
    identifiers = {rd.identifier for rd in manifest.resource_descriptors()}

    # Model file should be included
    assert "model.txt" in identifiers
    # Signature files should be excluded
    assert "model.sig" not in identifiers
    assert "backup.sig" not in identifiers


def test_attestation_files_always_excluded(tmp_path):
    """Test that attestation files are always excluded from hashing."""
    model = tmp_path / "model"
    model.mkdir()
    (model / "model.txt").write_text("model content")
    (model / "model.slsa.sigstore.json").write_text("SLSA provenance")
    (model / "model.spdx.sigstore.json").write_text("SBOM")
    (model / "claims.jsonl").write_text("bundled attestations")

    cfg = hashing.Config()
    manifest = cfg.hash(model)
    identifiers = {rd.identifier for rd in manifest.resource_descriptors()}

    # Model file should be included
    assert "model.txt" in identifiers
    # Attestation files should be excluded
    assert "model.slsa.sigstore.json" not in identifiers
    assert "model.spdx.sigstore.json" not in identifiers
    assert "claims.jsonl" not in identifiers


def test_attestation_exclusion_independent_of_ignore_git_paths(tmp_path):
    """Test attestations excluded by default regardless of ignore_git_paths.

    Verifies that ignore_git_paths setting doesn't affect attestation
    exclusion.
    """
    model = tmp_path / "model"
    model.mkdir()
    (model / "model.txt").write_text("model content")
    (model / "model.sig").write_text("signature")
    (model / ".gitignore").write_text("*.pyc")

    # Test with ignore_git_paths=False (but ignore_att_paths defaults to True)
    cfg_no_git = hashing.Config().set_ignored_paths(
        paths=[], ignore_git_paths=False
    )
    manifest_no_git = cfg_no_git.hash(model)
    identifiers_no_git = {
        rd.identifier for rd in manifest_no_git.resource_descriptors()
    }

    # .gitignore should be included when ignore_git_paths=False
    assert ".gitignore" in identifiers_no_git
    # But signature files should still be excluded
    # (ignore_att_paths defaults to True)
    assert "model.sig" not in identifiers_no_git

    # Test with ignore_git_paths=True (and ignore_att_paths defaults to True)
    cfg_with_git = hashing.Config().set_ignored_paths(
        paths=[], ignore_git_paths=True
    )
    manifest_with_git = cfg_with_git.hash(model)
    identifiers_with_git = {
        rd.identifier for rd in manifest_with_git.resource_descriptors()
    }

    # .gitignore should be excluded when ignore_git_paths=True
    assert ".gitignore" not in identifiers_with_git
    # Signature files should still be excluded
    assert "model.sig" not in identifiers_with_git


def test_ignore_att_paths_can_be_disabled(tmp_path):
    """Test that attestation exclusion can be disabled.

    Verifies that setting ignore_att_paths=False includes attestation files
    in the signature.
    """
    model = tmp_path / "model"
    model.mkdir()
    (model / "model.txt").write_text("model content")
    (model / "model.sig").write_text("signature")
    (model / "model.slsa.sigstore.json").write_text("SLSA provenance")

    # Test with ignore_att_paths=False (include attestations)
    cfg = hashing.Config().set_ignored_paths(paths=[], ignore_att_paths=False)
    manifest = cfg.hash(model)
    identifiers = {rd.identifier for rd in manifest.resource_descriptors()}

    # Model file should be included
    assert "model.txt" in identifiers
    # Attestation files should now be included
    assert "model.sig" in identifiers
    assert "model.slsa.sigstore.json" in identifiers


def test_glob_patterns_are_expanded(tmp_path):
    """Regression test: glob patterns must be expanded, not treated literally.

    This test validates that glob patterns like "*.sig" are properly expanded
    to match actual files, rather than being treated as literal path components.

    Without proper glob expansion, patterns would be interpreted as literal
    paths (e.g., looking for a file literally named "*.sig") and would not
    match any files, causing attestation files to be incorrectly included in
    signatures.
    """
    model = tmp_path / "model"
    model.mkdir()

    # Create model file
    (model / "model.txt").write_text("model content")

    # Create multiple files matching glob patterns
    (model / "model.sig").write_text("signature 1")
    (model / "backup.sig").write_text("signature 2")
    (model / "another.sig").write_text("signature 3")
    (model / "model.slsa.sigstore.json").write_text("SLSA provenance")
    (model / "scan.sbom.sigstore.json").write_text("SBOM")
    (model / "claims.jsonl").write_text("bundled claims")

    # Create a file that should NOT match any patterns
    (model / "data.json").write_text("data")

    # Hash with default configuration (ignore_att_paths=True)
    cfg = hashing.Config()
    manifest = cfg.hash(model)
    identifiers = {rd.identifier for rd in manifest.resource_descriptors()}

    # Model and data files should be included
    assert "model.txt" in identifiers
    assert "data.json" in identifiers

    # ALL files matching *.sig should be excluded
    assert "model.sig" not in identifiers
    assert "backup.sig" not in identifiers
    assert "another.sig" not in identifiers

    # ALL files matching *.sigstore.json should be excluded
    assert "model.slsa.sigstore.json" not in identifiers
    assert "scan.sbom.sigstore.json" not in identifiers

    # claims.jsonl (literal path) should be excluded
    assert "claims.jsonl" not in identifiers
