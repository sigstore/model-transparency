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

from contextlib import suppress
import os
from pathlib import Path

# type: ignore
import atheris

import model_signing


_SAFE_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"


def _consume_segment(
    fdp: atheris.FuzzedDataProvider, min_len: int = 1, max_len: int = 16
) -> str:
    """Return a path-safe segment using only _SAFE_CHARS."""
    seg_len = fdp.ConsumeIntInRange(min_len, max_len)
    bs = fdp.ConsumeBytes(seg_len)
    if not bs:
        return "x"
    out = []
    for b in bs:
        out.append(_SAFE_CHARS[b % len(_SAFE_CHARS)])
    s = "".join(out)
    if s in {".", "..", ""}:
        s = "x" + s + "x"
    return s


def random_relpath(fdp: atheris.FuzzedDataProvider) -> Path:
    """Generate a relative, nested path (no traversal, no absolute roots)."""
    depth = fdp.ConsumeIntInRange(1, 4)
    parts = [_consume_segment(fdp) for _ in range(depth)]
    if fdp.ConsumeBool():
        ext = _consume_segment(fdp, 1, 6).lower()
        parts[-1] = f"{parts[-1]}.{ext}"
    rel = Path(parts[0])
    for p in parts[1:]:
        rel = rel / p
    rel = Path(*[p for p in rel.parts if p not in ("", ".", "..")])
    if rel == Path():
        rel = Path("f")
    return rel


def is_under(child: Path, parent: Path) -> bool:
    """True iff 'child' is inside 'parent' after resolving symlinks."""
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except Exception:
        return False


def safe_write(root: Path, rel: Path, data: bytes) -> bool:
    """Write bytes to root/rel only if the resolved path stays under root.

    Uses an O_NOFOLLOW open (when supported) to avoid following a final
    symlink. Returns True if a regular file exists at the target after the
    write attempt.
    """
    dest_resolved = (root / rel).resolve()
    if not is_under(dest_resolved, root):
        return False

    try:
        dest_resolved.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        return False

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    nofollow = getattr(os, "O_NOFOLLOW", 0)

    try:
        if nofollow:
            fd = os.open(dest_resolved, flags | nofollow, 0o666)
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
            except Exception:
                with suppress(Exception):
                    os.close(fd)
        else:
            with open(dest_resolved, "wb") as f:
                f.write(data)
    except Exception:
        return False

    return dest_resolved.is_file()


def create_fuzz_files(root: Path, fdp: atheris.FuzzedDataProvider) -> int:
    """Create 0..30 files under root with fuzzed relative paths and contents.

    Returns the number of files successfully created.
    """
    nfiles = fdp.ConsumeIntInRange(0, 30)
    seen: set[Path] = set()
    created = 0
    for _ in range(nfiles):
        rel = random_relpath(fdp)
        if rel in seen:
            continue
        seen.add(rel)

        size = fdp.ConsumeIntInRange(0, 64 * 1024)
        data = fdp.ConsumeBytes(size)
        if safe_write(root, rel, data):
            created += 1
    return created


def any_files(root: Path) -> bool:
    """True if there is at least one regular file under root."""
    return any(p.is_file() for p in root.rglob("*"))


def _build_hashing_config_from_fdp(
    fdp: atheris.FuzzedDataProvider,
) -> "model_signing.hashing.Config":
    """Randomize serialization strategy and hash algorithm."""
    alg = ["sha256", "blake2", "blake3"][fdp.ConsumeIntInRange(0, 2)]

    hcfg = model_signing.hashing.Config()
    # Choose serialization mode: file vs shard
    if fdp.ConsumeBool():
        # File-based serialization.
        hcfg.use_file_serialization(hashing_algorithm=alg)
    else:
        # Sharded file serialization
        hcfg.use_shard_serialization(hashing_algorithm=alg)
    return hcfg
