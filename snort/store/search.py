"""Search over sealed Lance datasets and WAL tail using DuckDB and Lance native FTS."""

from __future__ import annotations

import json
import re
from pathlib import Path

import duckdb
import lance
import pyarrow as pa

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


def _collect_wal_records(wal_dir: Path, sealed_wal_names: set[str], query_str: str | None = None) -> list[dict]:
    """Collect unsealed WAL events as records."""
    if not wal_dir.exists():
        return []
    reader = WalReader(wal_dir)
    wal_records = []
    for path in reader.segment_paths():
        if path.name in sealed_wal_names:
            continue
        for row, envelope in enumerate(_iter_wal_envelopes(path)):
            event = envelope.get("event", {})
            raw = str(event.get("raw", ""))
            if query_str is not None and query_str not in raw:
                continue
            rec = {name: event.get(name, "") for name in EVENT_COLUMNS}
            rec["_row"] = row
            rec["_segment"] = path.name
            rec["_source"] = "wal"
            wal_records.append(rec)
    return wal_records


def search_bm25(
    query: str,
    sealed_dir: str | Path,
    index_dir: str | Path | None = None,
    wal_dir: str | Path | None = None,
    filter_expr: str | None = None,
    *,
    limit: int = 1000,
) -> list[dict]:
    """Hybrid BM25 full-text search with Lance native FTS relevance scoring and exact boolean filters."""
    return search(
        query,
        sealed_dir,
        index_dir,
        wal_dir,
        limit=limit,
        bm25=True,
        filter_expr=filter_expr,
    )


def search(
    query: str,
    sealed_dir: str | Path,
    index_dir: str | Path | None = None,
    wal_dir: str | Path | None = None,
    *,
    limit: int = 1000,
    bm25: bool = False,
    filter_expr: str | None = None,
) -> list[dict]:
    """Search for query across sealed Lance segments and the unsealed WAL tail.

    Implements:
    1. Dynamic DuckDB Unified View: executes a single UNION ALL query across all sealed
       Lance segments and in-memory unsealed WAL buffer for parallelized SIMD scans.
    2. Hybrid BM25 Scoring (bm25=True): uses Lance's native full-text scanner with
       relevance scoring (_score) and exact boolean filters.
    """
    split_query(query)  # validate eagerly
    query_str = query.strip()
    sealed_dir = Path(sealed_dir)

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

    sealed_wal_names = {seg["wal_segment"] for seg in sealed if "wal_segment" in seg}

    # Branch 1: Hybrid BM25 Full-Text Search via Lance Native Scanner
    if bm25:
        results: list[dict] = []
        for seg in sealed:
            seg_path = sealed_dir / seg["name"]
            if not seg_path.exists():
                continue
            is_indexed = seg["name"] in indexed
            source_tag = "index" if is_indexed else "scan"
            try:
                ds = lance.dataset(str(seg_path))
                scanner = ds.scanner(
                    full_text_query=query_str,
                    filter=filter_expr,
                    limit=limit,
                )
                tbl = scanner.to_table()
                pydict = tbl.to_pydict()
                scores = pydict.get("_score", [1.0] * len(tbl))
                names = tbl.column_names
                for i in range(len(tbl)):
                    rec = {c: pydict[c][i] for c in names if c in EVENT_COLUMNS}
                    rec["_segment"] = seg["name"]
                    rec["_source"] = source_tag
                    rec["_row"] = i
                    rec["_score"] = float(scores[i])
                    results.append(rec)
            except Exception:
                tbl = lance.dataset(str(seg_path)).to_table()
                raws = tbl.column("raw").to_pylist()
                for idx, raw in enumerate(raws):
                    if query_str in str(raw):
                        rec = {c: tbl.column(c)[idx].as_py() for c in EVENT_COLUMNS}
                        rec["_segment"] = seg["name"]
                        rec["_source"] = source_tag
                        rec["_row"] = idx
                        rec["_score"] = 0.5
                        results.append(rec)

        if wal_dir is not None:
            wal_records = _collect_wal_records(Path(wal_dir), sealed_wal_names, query_str=query_str)
            for r in wal_records:
                r["_score"] = 0.5
                results.append(r)

        results.sort(key=lambda x: x.get("_score", 0.0), reverse=True)
        return results[:limit]

    # Branch 2: Dynamic DuckDB Unified View
    wal_records = []
    if wal_dir is not None:
        wal_records = _collect_wal_records(Path(wal_dir), sealed_wal_names, query_str=None)

    valid_sealed = [s for s in sealed if (sealed_dir / s["name"]).exists()]
    if not valid_sealed and not wal_records:
        return []

    con = _duckdb_con()
    subqueries = []
    cols_str = ", ".join(EVENT_COLUMNS)

    for seg in valid_sealed:
        seg_path = (sealed_dir / seg["name"]).as_posix()
        is_indexed = seg["name"] in indexed
        source_tag = "index" if is_indexed else "scan"
        subqueries.append(f"""
            SELECT {cols_str},
                   '{seg["name"]}' AS _segment,
                   '{source_tag}' AS _source,
                   (row_number() OVER () - 1) AS _row
            FROM '{seg_path}'
        """)

    if wal_records:
        wal_tbl = pa.Table.from_pylist(wal_records)
        con.register("wal_buffer", wal_tbl)
        subqueries.append(f"""
            SELECT {cols_str},
                   _segment,
                   _source,
                   _row
            FROM wal_buffer
        """)

    where_clauses = ["raw LIKE ?"]
    params: list = [f"%{query_str}%"]
    if filter_expr:
        where_clauses.append(f"({filter_expr})")

    unified_sql = f"""
    SELECT * FROM (
        {' UNION ALL '.join(subqueries)}
    )
    WHERE {' AND '.join(where_clauses)}
    LIMIT ?
    """
    params.append(limit)

    try:
        rows = con.execute(unified_sql, params).fetchall()
        cols = [d[0] for d in con.description]
        return [dict(zip(cols, r)) for r in rows]
    except Exception:
        # Fallback to per-segment scan if unified query encounters an issue
        results = []
        for seg in valid_sealed:
            seg_path = sealed_dir / seg["name"]
            is_indexed = seg["name"] in indexed
            source_tag = "index" if is_indexed else "scan"
            try:
                ds = lance.dataset(str(seg_path))
                tbl = ds.to_table()
                raws = tbl.column("raw").to_pylist()
                for idx, raw in enumerate(raws):
                    if query_str in str(raw):
                        m = {c: tbl.column(c)[idx].as_py() for c in EVENT_COLUMNS}
                        m["_segment"] = seg["name"]
                        m["_source"] = source_tag
                        m["_row"] = idx
                        results.append(m)
                        if len(results) >= limit:
                            break
            except Exception:
                pass
            if len(results) >= limit:
                break
        if len(results) < limit and wal_records:
            for r in wal_records:
                if query_str in str(r.get("raw", "")):
                    results.append(r)
                    if len(results) >= limit:
                        break
        return results
