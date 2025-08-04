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
