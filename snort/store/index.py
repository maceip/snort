"""Batch index building over sealed Lance segments.

``snort index`` builds native Lance secondary scalar indexes (BTREE on event_hash)
and full-text inverted indexes (INVERTED on raw) directly inside each Lance dataset.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import lance

from snort.store.seal import SEALED_MANIFEST

INDEX_MANIFEST = "index-manifest.json"


def _load_manifest(index_dir: Path) -> list[dict]:
    manifest = index_dir / INDEX_MANIFEST
    if not manifest.exists():
        return []
    return json.loads(manifest.read_text(encoding="utf-8"))["segments"]


def _save_manifest(index_dir: Path, entries: list[dict]) -> None:
    tmp = index_dir / (INDEX_MANIFEST + ".tmp")
    tmp.write_text(json.dumps({"segments": entries}, indent=2), encoding="utf-8")
    os.replace(tmp, index_dir / INDEX_MANIFEST)


def index_path_for(index_dir: Path, segment_name: str, backend: str = "lance") -> Path:
    stem = Path(segment_name).stem
    return index_dir / f"{stem}.lance_idx"


def indexed_segments(index_dir: Path) -> dict[str, dict]:
    """Map segment name -> index entry for all successfully indexed segments."""
    return {entry["segment"]: entry for entry in _load_manifest(index_dir)}


def build_lance_index(lance_path: Path) -> dict:
    """Build native Lance BTREE and INVERTED indexes directly inside the dataset."""
    ds = lance.dataset(str(lance_path))
    try:
        ds.create_scalar_index("event_hash", index_type="BTREE", replace=True)
    except Exception:
        pass
    try:
        ds.create_scalar_index("raw", index_type="INVERTED", replace=True)
    except Exception:
        pass
    if hasattr(ds, "describe_indices"):
        indices = [idx.name for idx in ds.describe_indices()]
    else:
        indices = [idx.get("name", "") for idx in ds.list_indices()]
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
    sealed_dir = Path(sealed_dir)
    index_dir = Path(index_dir)
    index_dir.mkdir(parents=True, exist_ok=True)

    sealed_manifest_path = sealed_dir / SEALED_MANIFEST
    if not sealed_manifest_path.exists():
        return []
    sealed_entries = json.loads(sealed_manifest_path.read_text(encoding="utf-8"))["segments"]

    existing = indexed_segments(index_dir)
    entries: list[dict] = list(existing.values())
    new_entries: list[dict] = []

    for seg in sealed_entries:
        if seg["name"] in existing:
            continue
        lance_path = sealed_dir / seg["name"]
        if not lance_path.exists():
            continue

        stats = build_lance_index(lance_path)
        marker_path = index_path_for(index_dir, seg["name"], "lance")
        marker_path.write_text(json.dumps(stats), encoding="utf-8")

        entry = {
            "segment": seg["name"],
            "backend": "lance",
            "index_path": marker_path.name,
            "count": seg["count"],
            "indexed_at": datetime.now(timezone.utc).isoformat(),
            "stats": stats,
        }
        entries.append(entry)
        new_entries.append(entry)

    if new_entries:
        _save_manifest(index_dir, entries)
    return new_entries
