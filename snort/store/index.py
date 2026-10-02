"""Batch index building over sealed Lance segments.

``snort index`` builds native Lance secondary scalar indexes (BTREE on event_hash)
and full-text inverted indexes (INVERTED on raw) directly inside each Lance dataset.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import lance

from snort.store.seal import SEALED_MANIFEST
from snort.persistence import atomic_write

INDEX_MANIFEST = "index-manifest.json"


def _load_manifest(index_dir: Path) -> list[dict]:
    manifest = index_dir / INDEX_MANIFEST
    if not manifest.exists():
        return []
    return json.loads(manifest.read_text(encoding="utf-8"))["segments"]


def _save_manifest(index_dir: Path, entries: list[dict]) -> None:
    atomic_write(
        index_dir / INDEX_MANIFEST, json.dumps({"segments": entries}, indent=2)
    )


def index_path_for(index_dir: Path, segment_name: str, backend: str = "lance") -> Path:
    stem = Path(segment_name).stem
    return index_dir / f"{stem}.lance_idx"


def indexed_segments(index_dir: Path) -> dict[str, dict]:
    """Map segment name -> index entry for all successfully indexed segments."""
    return {entry["segment"]: entry for entry in _load_manifest(index_dir)}


def build_lance_index(lance_path: Path) -> dict:
    """Build native Lance BTREE and INVERTED indexes directly inside the dataset."""
    ds = lance.dataset(str(lance_path))
    ds.create_scalar_index("event_hash", index_type="BTREE", replace=True)
    ds.create_scalar_index("raw", index_type="INVERTED", replace=True)
    if hasattr(ds, "describe_indices"):
        indices = [idx.name for idx in ds.describe_indices()]
    else:
        indices = [idx.get("name", "") for idx in ds.list_indices()]
    if not {"event_hash_idx", "raw_idx"}.issubset(indices):
        raise RuntimeError(f"required native indexes are missing: {indices}")
    return {
        "backend": "lance",
        "rows": ds.count_rows(),
        "indices": indices,
    }


def build_index(
    sealed_dir: str | Path,
    index_dir: str | Path,
    work_dir: str | Path | None = None,
    *,
    backend: str = "auto",
) -> list[dict]:
    """Index every unindexed sealed Lance segment. Idempotent."""
    if backend not in ("auto", "lance", "builtin"):
        raise ValueError(f"unsupported index backend: {backend}")
    sealed_dir = Path(sealed_dir)
    index_dir = Path(index_dir)
    index_dir.mkdir(parents=True, exist_ok=True)

    sealed_manifest_path = sealed_dir / SEALED_MANIFEST
    if not sealed_manifest_path.exists():
        return []
    sealed_entries = json.loads(sealed_manifest_path.read_text(encoding="utf-8"))[
        "segments"
    ]

    existing = indexed_segments(index_dir)
    entries: dict[str, dict] = dict(existing)
    new_entries: list[dict] = []

    for seg in sealed_entries:
        lance_path = sealed_dir / seg["name"]
        if not lance_path.exists():
            raise FileNotFoundError(lance_path)
        if seg["name"] in existing:
            names = {
                idx.name for idx in lance.dataset(str(lance_path)).describe_indices()
            }
            if {"event_hash_idx", "raw_idx"}.issubset(names):
                continue

        stats = build_lance_index(lance_path)
        marker_path = index_path_for(index_dir, seg["name"], "lance")
        atomic_write(marker_path, json.dumps(stats))

        entry = {
            "segment": seg["name"],
            "backend": "lance",
            "index_path": marker_path.name,
            "count": seg["count"],
            "indexed_at": datetime.now(timezone.utc).isoformat(),
            "stats": stats,
        }
        entries[seg["name"]] = entry
        new_entries.append(entry)

    if new_entries:
        _save_manifest(index_dir, list(entries.values()))
    return new_entries
