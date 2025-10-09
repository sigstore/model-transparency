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
