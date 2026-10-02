"""Batch index building over sealed segments (plan section 4.1).

``snort index`` indexes the ``raw`` column of each sealed segment as a
batch step. Indexing runs one segment at a time in a dedicated working
directory: LogCrisp writes intermediate files into its cwd, is not
reentrant, and can crash on bad input, so the LogCloud backend runs in
an isolated helper subprocess (see ``snort.store.logcloud_helper``).

Backends:
- ``logcloud``: rottnest 1.5.0 LogCloud (``pip install snort[logcloud]``).
- ``builtin``: a 4-gram inverted index over ``raw`` with identical
  split-and-verify search semantics. This is the default and needs no
  extra dependencies; ``auto`` uses LogCloud when importable.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pyarrow.parquet as pq

from snort.store.seal import SEALED_MANIFEST

INDEX_MANIFEST = "index-manifest.json"
NGRAM_N = 4
MAX_RAW_CHARS = 32_768


def _load_manifest(index_dir: Path) -> list[dict]:
    manifest = index_dir / INDEX_MANIFEST
    if not manifest.exists():
        return []
    return json.loads(manifest.read_text(encoding="utf-8"))["segments"]


def _save_manifest(index_dir: Path, entries: list[dict]) -> None:
    tmp = index_dir / (INDEX_MANIFEST + ".tmp")
    tmp.write_text(json.dumps({"segments": entries}, indent=2), encoding="utf-8")
    os.replace(tmp, index_dir / INDEX_MANIFEST)


def index_path_for(index_dir: Path, segment_name: str, backend: str) -> Path:
    stem = Path(segment_name).stem
    suffix = ".logcloud" if backend == "logcloud" else ".ngram.json.zst"
    return index_dir / f"{stem}{suffix}"


def ngrams(text: str, n: int = NGRAM_N) -> set[str]:
    lowered = text.lower()
    if len(lowered) < n:
        return set()
    return {lowered[i : i + n] for i in range(len(lowered) - n + 1)}


def build_builtin_index(parquet_path: Path, out_path: Path) -> dict:
    """Build a 4-gram inverted index over the ``raw`` column."""
    table = pq.read_table(parquet_path, columns=["raw"])
    raws = table.column("raw").to_pylist()
    postings: dict[str, list[int]] = {}
    for row, raw in enumerate(raws):
        for gram in ngrams(str(raw)[:MAX_RAW_CHARS]):
            postings.setdefault(gram, []).append(row)
    payload = {"version": 1, "backend": "builtin", "n": NGRAM_N, "rows": len(raws), "postings": postings}
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    try:
        import zstandard as zstd

        data = zstd.ZstdCompressor(level=3).compress(data)
    except ImportError:
        pass
    out_path.write_bytes(data)
    return {"rows": len(raws), "terms": len(postings), "bytes": out_path.stat().st_size}


def load_builtin_index(path: Path) -> dict:
    data = path.read_bytes()
    if path.suffix == ".zst":
        try:
            import zstandard as zstd

            data = zstd.ZstdDecompressor().decompress(data)
        except ImportError as exc:
            raise RuntimeError(f"cannot read {path}: zstandard is not installed") from exc
    return json.loads(data.decode("utf-8"))


def _logcloud_available() -> bool:
    try:
        import rottnest  # noqa: F401

        return True
    except ImportError:
        return False


def build_logcloud_index(parquet_path: Path, out_path: Path, work_dir: Path) -> dict:
    """Index one segment with rottnest LogCloud in an isolated helper process."""
    work_dir.mkdir(parents=True, exist_ok=True)
    helper = Path(__file__).with_name("logcloud_helper.py")
    proc = subprocess.run(
        [sys.executable, str(helper), "index", str(parquet_path), "raw", out_path.stem],
        cwd=work_dir,
        capture_output=True,
        text=True,
        timeout=3600,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"logcloud helper failed for {parquet_path.name}: {proc.stderr[-2000:]}")
    return json.loads(proc.stdout.strip().splitlines()[-1])


def build_index(
    sealed_dir: str | Path,
    index_dir: str | Path,
    work_dir: str | Path | None = None,
    *,
    backend: str = "auto",
) -> list[dict]:
    """Index every sealed segment that has no index yet. Idempotent.

    One segment at a time, in a dedicated working directory. Returns the
    manifest entries for newly indexed segments.
    """
    sealed_dir = Path(sealed_dir)
    index_dir = Path(index_dir)
    index_dir.mkdir(parents=True, exist_ok=True)
    work = Path(work_dir) if work_dir else index_dir / "_work"
    work.mkdir(parents=True, exist_ok=True)
    manifest_path = sealed_dir / SEALED_MANIFEST
    if not manifest_path.exists():
        return []
    sealed = json.loads(manifest_path.read_text(encoding="utf-8"))["segments"]
    indexed = _load_manifest(index_dir)
    done = {entry["segment"] for entry in indexed}
    new_entries: list[dict] = []
    for seg in sealed:
        if seg["name"] in done:
            continue
        parquet_path = sealed_dir / seg["name"]
        if not parquet_path.exists():
            continue
        chosen = backend
        if chosen == "auto":
            chosen = "logcloud" if _logcloud_available() else "builtin"
        out_path = index_path_for(index_dir, seg["name"], chosen)
        if chosen == "logcloud":
            stats = build_logcloud_index(parquet_path, out_path, work)
        else:
            stats = build_builtin_index(parquet_path, out_path)
        entry = {
            "segment": seg["name"],
            "backend": chosen,
            "rows": stats.get("rows", seg["count"]),
            "indexed_at": datetime.now(tz=timezone.utc).isoformat(),
        }
        indexed.append(entry)
        new_entries.append(entry)
        _save_manifest(index_dir, indexed)
    return new_entries


def indexed_segments(index_dir: str | Path) -> dict[str, dict]:
    """Map sealed segment name to its index manifest entry."""
    index_dir = Path(index_dir)
    return {entry["segment"]: entry for entry in _load_manifest(index_dir)}
