"""Search over sealed Lance datasets using DuckDB."""

from __future__ import annotations

import json
import re
from pathlib import Path

import duckdb

from snort.ingest.events import EVENT_COLUMNS
from snort.ingest.wal import WalReader, _read_lines
from snort.store.index import indexed_segments

BOUNDARY_RE = re.compile(r"[\s:;,=()\[\]{}\"']+")


def split_query(query: str) -> list[str]:
    """Split a query into parts, longest first."""
    if not query or not query.strip():
        raise ValueError("search query must not be empty")
    parts = [part for part in BOUNDARY_RE.split(query.strip()) if part]
    if not parts:
        raise ValueError(f"query has no searchable parts: {query!r}")
    return sorted(parts, key=len, reverse=True)


def _duckdb_con() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect()
    try:
        con.execute("LOAD lance;")
    except Exception:
        con.execute("INSTALL lance; LOAD lance;")
    return con


def _iter_wal_envelopes(path: Path):
    for line in _read_lines(path):
        line = line.strip()
        if line:
            yield json.loads(line)


def search(
    query: str,
    sealed_dir: str | Path,
    index_dir: str | Path | None = None,
    wal_dir: str | Path | None = None,
    *,
    limit: int = 1000,
) -> list[dict]:
    """Search for query across sealed Lance segments and the unsealed WAL tail."""
    split_query(query)  # validate eagerly
    query_str = query.strip()

    sealed_dir = Path(sealed_dir)
    results: list[dict] = []

    indexed = set()
    if index_dir is not None:
        idx_p = Path(index_dir)
        if idx_p.exists():
            indexed = set(indexed_segments(idx_p).keys())

    manifest_path = sealed_dir / "sealed-manifest.json"
    sealed = []
    if manifest_path.exists():
        try:
            sealed = json.loads(manifest_path.read_text(encoding="utf-8")).get("segments", [])
        except Exception:
            pass

    if sealed:
        con = _duckdb_con()
        for seg in sealed:
            seg_path = sealed_dir / seg["name"]
            if not seg_path.exists():
                continue
            is_indexed = seg["name"] in indexed
            source_tag = "index" if is_indexed else "scan"
            pattern = f"%{query_str}%"
            try:
                rows = con.execute(
                    f"SELECT * FROM '{seg_path.as_posix()}' WHERE raw LIKE ? LIMIT ?",
                    [pattern, limit - len(results)],
                ).fetchall()
                cols = [d[0] for d in con.description]
                for r in rows:
                    m = dict(zip(cols, r))
                    m["_segment"] = seg["name"]
                    m["_source"] = source_tag
                    results.append(m)
                    if len(results) >= limit:
                        break
            except Exception:
                import lance
                ds = lance.dataset(str(seg_path))
                tbl = ds.to_table()
                raws = tbl.column("raw").to_pylist()
                for idx, raw in enumerate(raws):
                    if query_str in str(raw):
                        m = {c: tbl.column(c)[idx].as_py() for c in EVENT_COLUMNS}
                        m["_segment"] = seg["name"]
                        m["_source"] = source_tag
                        results.append(m)
                        if len(results) >= limit:
                            break
            if len(results) >= limit:
                break

    # Also scan unsealed WAL tail
    if wal_dir is not None and len(results) < limit:
        wal_p = Path(wal_dir)
        if wal_p.exists():
            reader = WalReader(wal_p)
            sealed_wal = {seg["wal_segment"] for seg in sealed}
            for path in reader.segment_paths():
                if path.name in sealed_wal:
                    continue  # already covered by the sealed scan
                for row, envelope in enumerate(_iter_wal_envelopes(path)):
                    if len(results) >= limit:
                        break
                    event = envelope.get("event", {})
                    if query_str in str(event.get("raw", "")):
                        record = {name: event.get(name, "") for name in EVENT_COLUMNS}
                        record["_row"] = row
                        record["_segment"] = path.name
                        record["_source"] = "wal"
                        results.append(record)

    return results
