"""Seal WAL segments to Lance datasets (plan section 4.1).

Each hour (or 256 MB) the WAL is written to Lance datasets we control.
Columns are the Event schema (``EVENT_COLUMNS``). A ``sealed-manifest.json``
chains every sealed segment to the previous one, extending the
tamper-evident lineage from the WAL.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pyarrow as pa
import lance

from snort.ingest.events import EVENT_COLUMNS
from snort.ingest.wal import MANIFEST_NAME, _read_lines
from snort.persistence import atomic_write

SEALED_MANIFEST = "sealed-manifest.json"


def _sealed_name(seq: int) -> str:
    return f"seg-{seq:06d}.lance"


def _lance_data_hash(lance_dir: Path) -> str:
    hasher = hashlib.blake3() if hasattr(hashlib, "blake3") else hashlib.sha256()
    data_dir = lance_dir / "data"
    if data_dir.exists():
        for p in sorted(data_dir.rglob("*")):
            if p.is_file():
                hasher.update(p.name.encode("utf-8"))
                hasher.update(p.read_bytes())
    else:
        for p in sorted(lance_dir.rglob("*")):
            if p.is_file() and "_indices" not in p.parts:
                hasher.update(p.name.encode("utf-8"))
                hasher.update(p.read_bytes())
    return hasher.hexdigest()


def _load_manifest(sealed_dir: Path) -> list[dict]:
    manifest = sealed_dir / SEALED_MANIFEST
    if not manifest.exists():
        return []
    return json.loads(manifest.read_text(encoding="utf-8"))["segments"]


def seal_segments(
    wal_dir: str | Path,
    sealed_dir: str | Path,
    *,
    row_group_size: int = 100_000,
    **kwargs,
) -> list[dict]:
    """Seal every unsealed WAL segment to Lance. Idempotent.

    Returns the manifest entries for newly sealed segments.
    """
    wal_dir = Path(wal_dir)
    sealed_dir = Path(sealed_dir)
    sealed_dir.mkdir(parents=True, exist_ok=True)
    wal_manifest_path = wal_dir / MANIFEST_NAME
    if not wal_manifest_path.exists():
        return []
    wal_entries = json.loads(wal_manifest_path.read_text(encoding="utf-8"))["segments"]
    sealed = _load_manifest(sealed_dir)
    done = {entry["wal_segment"] for entry in sealed}
    prev_root = sealed[-1]["root"] if sealed else "GENESIS"
    sealed_seq = max((entry["seq"] for entry in sealed), default=0)
    new_entries: list[dict] = []
    for wal_entry in wal_entries:
        if wal_entry["name"] in done:
            continue
        wal_path = wal_dir / wal_entry["name"]
        if not wal_path.exists():
            raise FileNotFoundError(f"manifested WAL segment is missing: {wal_path}")
        events = []
        for line in _read_lines(wal_path):
            line = line.strip()
            if line:
                events.append(json.loads(line)["event"])
        columns: dict[str, list] = {name: [] for name in EVENT_COLUMNS}
        for event in events:
            for name in EVENT_COLUMNS:
                value = event.get(
                    name, 0 if name in ("source_seq", "flux_tags") else ""
                )
                columns[name].append(
                    int(value or 0)
                    if name in ("source_seq", "flux_tags")
                    else str(value)
                )
        table = pa.table(
            {
                name: pa.array(
                    columns[name],
                    type=pa.int64()
                    if name in ("source_seq", "flux_tags")
                    else pa.string(),
                )
                for name in EVENT_COLUMNS
            }
        )
        sealed_seq += 1
        out_path = sealed_dir / _sealed_name(sealed_seq)
        lance.write_dataset(table, str(out_path), mode="overwrite")
        root = _lance_data_hash(out_path)
        entry = {
            "seq": sealed_seq,
            "name": out_path.name,
            "wal_segment": wal_entry["name"],
            "wal_root": wal_entry["root"],
            "count": len(events),
            "prev_root": prev_root,
            "root": root,
        }
        sealed.append(entry)
        new_entries.append(entry)
        prev_root = root
    if new_entries:
        atomic_write(
            sealed_dir / SEALED_MANIFEST, json.dumps({"segments": sealed}, indent=2)
        )
    return new_entries


def verify_sealed_chain(wal_dir: str | Path, sealed_dir: str | Path) -> dict:
    """Verify sealed segments against the WAL roots and the chain."""
    sealed_dir = Path(sealed_dir)
    errors: list[str] = []
    entries = _load_manifest(sealed_dir)
    wal_roots = {}
    wal_manifest_path = Path(wal_dir) / MANIFEST_NAME
    if wal_manifest_path.exists():
        for entry in json.loads(wal_manifest_path.read_text(encoding="utf-8"))[
            "segments"
        ]:
            wal_roots[entry["name"]] = entry["root"]
    prev_root = "GENESIS"
    events = 0
    for entry in entries:
        if entry["prev_root"] != prev_root:
            errors.append(f"{entry['name']}: sealed chain link broken")
        path = sealed_dir / entry["name"]
        if not path.exists():
            errors.append(f"{entry['name']}: missing lance dataset")
            continue
        if _lance_data_hash(path) != entry["root"]:
            errors.append(f"{entry['name']}: lance hash mismatch")
        wal_root = wal_roots.get(entry["wal_segment"])
        if wal_root is not None and wal_root != entry["wal_root"]:
            errors.append(f"{entry['name']}: WAL root mismatch")
        try:
            ds = lance.dataset(str(path))
            got = ds.count_rows()
        except Exception as exc:
            errors.append(f"{entry['name']}: unreadable lance dataset: {exc}")
            continue
        if got != entry["count"]:
            errors.append(
                f"{entry['name']}: count mismatch (manifest {entry['count']}, lance {got})"
            )
        events += entry["count"]
        prev_root = entry["root"]
    return {
        "ok": not errors,
        "segments_checked": len(entries),
        "events": events,
        "errors": errors,
    }
