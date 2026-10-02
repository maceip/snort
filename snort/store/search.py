"""Split-and-verify evidence search (plan section 4.1).

Required because of the boundary-query problem (assessment
logcloud.md): a query like ``10.10.34.20:72349`` spans two indexed
variables, so searching it whole returns nothing. The wrapper:

1. splits the query into variable-shaped parts;
2. searches the most selective part (rarest index postings; parts that
   hit the dictionary are tried last);
3. reads only the row groups holding candidates and keeps rows whose
   ``raw`` contains the full query string;
4. scans unsealed and not-yet-indexed segments directly (DuckDB over
   Parquet, substring scan over the WAL tail).

The verify step decides every match, so recall always equals a
brute-force substring scan (grep); the index only narrows the read.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pyarrow.parquet as pq

from snort.ingest.events import EVENT_COLUMNS
from snort.ingest.wal import WalReader
from snort.store.index import NGRAM_N, indexed_segments, index_path_for, load_builtin_index, ngrams

BOUNDARY_RE = re.compile(r"[\s:;,=()\[\]{}\"']+")


def split_query(query: str) -> list[str]:
    """Split a query into variable-shaped parts, longest first.

    ``10.10.34.20:72349`` becomes ``["10.10.34.20", "72349"]``;
    ``src: /10.10.34.22`` becomes ``["src", "/10.10.34.22"]``.
    Empty parts are dropped; the order is by decreasing length so the
    most selective part is tried first.
    """
    if not query or not query.strip():
        raise ValueError("search query must not be empty")
    parts = [part for part in BOUNDARY_RE.split(query.strip()) if part]
    if not parts:
        raise ValueError(f"query has no searchable parts: {query!r}")
    return sorted(parts, key=len, reverse=True)


def _candidate_rows(postings: dict, part: str) -> set[int] | None:
    """Rows containing every n-gram of ``part``; None when unindexable."""
    grams = ngrams(part)
    if not grams:
        return None
    candidates: set[int] | None = None
    for gram in grams:
        rows = postings.get(gram)
        if not rows:
            return set()
        rows_set = set(rows)
        candidates = rows_set if candidates is None else candidates & rows_set
        if not candidates:
            return set()
    return candidates if candidates is not None else set()


def _selective_part(postings: dict, parts: list[str]) -> tuple[str, set[int] | None]:
    """Pick the part with the smallest posting footprint (most selective).

    Parts with no usable n-grams cost infinity and are tried last, per
    the plan: dictionary/common hits never drive the lookup.
    """
    best: tuple[str, set[int] | None] | None = None
    best_cost: float | None = None
    for part in parts:
        candidates = _candidate_rows(postings, part)
        if candidates is None:
            cost = float("inf")
        else:
            cost = sum(len(postings.get(gram, [])) for gram in ngrams(part))
        if best is None or cost < (best_cost if best_cost is not None else float("inf")):
            best = (part, candidates)
            best_cost = cost
    assert best is not None
    return best


def _read_candidate_rows(parquet_path: Path, rows: set[int]) -> list[dict]:
    """Read only the row groups holding ``rows``, in row order."""
    if not rows:
        return []
    handle = pq.ParquetFile(parquet_path)
    group_sizes = [handle.metadata.row_group(group).num_rows for group in range(handle.metadata.num_row_groups)]
    offsets = [0]
    for size in group_sizes:
        offsets.append(offsets[-1] + size)
    wanted = sorted({row for row in rows if row < offsets[-1]})
    by_group: dict[int, list[tuple[int, int]]] = {}
    for row in wanted:
        group = next(g for g in range(len(group_sizes)) if offsets[g] <= row < offsets[g + 1])
        by_group.setdefault(group, []).append((row, row - offsets[group]))
    out: dict[int, dict] = {}
    for group, pairs in by_group.items():
        table = handle.read_row_group(group, columns=EVENT_COLUMNS)
        for global_row, local_row in pairs:
            out[global_row] = {name: table.column(name)[local_row].as_py() for name in EVENT_COLUMNS} | {"_row": global_row}
    return [out[row] for row in sorted(out)]


def _search_indexed_builtin(parquet_path: Path, index_entry: dict, index_dir: Path, query: str) -> list[dict]:
    index = load_builtin_index(index_path_for(index_dir, index_entry["segment"], "builtin"))
    postings = index["postings"]
    _, candidates = _selective_part(postings, split_query(query))
    if candidates is None:
        # Query too short for n-gram lookup: verify every row.
        table = pq.read_table(parquet_path, columns=EVENT_COLUMNS)
        rows = range(table.num_rows)
        matches = []
        for row in rows:
            raw = table.column("raw")[row].as_py()
            if query in str(raw):
                matches.append({name: table.column(name)[row].as_py() for name in EVENT_COLUMNS} | {"_row": row})
        return matches
    rows = _read_candidate_rows(parquet_path, candidates)
    return [record for record in rows if query in str(record["raw"])]


def _like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _search_unindexed_duckdb(parquet_path: Path, query: str) -> list[dict]:
    import duckdb

    pattern = f"%{_like_escape(query)}%"
    cols = ", ".join(EVENT_COLUMNS)
    cursor = duckdb.execute(
        f"SELECT {cols} FROM read_parquet(?) WHERE raw LIKE ? ESCAPE '\\'",
        [str(parquet_path), pattern],
    )
    matches = []
    for i, row in enumerate(cursor.fetchall()):
        matches.append(dict(zip(EVENT_COLUMNS, row)) | {"_row": i})
    return matches


def search(
    query: str,
    sealed_dir: str | Path,
    index_dir: str | Path,
    wal_dir: str | Path | None = None,
    *,
    limit: int = 1000,
) -> list[dict]:
    """Split-and-verify search over indexed, unindexed and WAL segments.

    Returns matching events in (segment sequence, row) order, each with
    ``_segment`` (parquet name or WAL name), ``_row`` and ``_source``
    (``index``, ``scan`` or ``wal``). Raises ValueError on empty queries.
    """
    split_query(query)  # validate eagerly
    sealed_dir = Path(sealed_dir)
    index_dir = Path(index_dir)
    manifest_path = sealed_dir / "sealed-manifest.json"
    sealed = []
    if manifest_path.exists():
        sealed = json.loads(manifest_path.read_text(encoding="utf-8"))["segments"]
    indexed = indexed_segments(index_dir)
    matches: list[dict] = []

    for seg in sealed:
        if len(matches) >= limit:
            break
        parquet_path = sealed_dir / seg["name"]
        if not parquet_path.exists():
            continue
        entry = indexed.get(seg["name"])
        if entry is not None and entry.get("backend") == "builtin":
            found = _search_indexed_builtin(parquet_path, entry, index_dir, query)
            source = "index"
        else:
            found = _search_unindexed_duckdb(parquet_path, query)
            source = "scan"
        for record in found:
            if len(matches) >= limit:
                break
            matches.append(record | {"_segment": seg["name"], "_source": source})

    if wal_dir is not None and len(matches) < limit:
        reader = WalReader(wal_dir)
        sealed_wal = {seg["wal_segment"] for seg in sealed}
        for path in reader.segment_paths():
            if path.name in sealed_wal:
                continue  # already covered by the sealed scan
            for row, envelope in enumerate(_iter_wal_envelopes(path)):
                if len(matches) >= limit:
                    break
                event = envelope.get("event", {})
                if query in str(event.get("raw", "")):
                    record = {name: event.get(name, "") for name in EVENT_COLUMNS}
                    record["_row"] = row
                    matches.append(record | {"_segment": path.name, "_source": "wal"})
    return matches


def _iter_wal_envelopes(path: Path):
    from snort.ingest.wal import _read_lines

    for line in _read_lines(path):
        line = line.strip()
        if line:
            yield json.loads(line)
