"""Consistent sealed/live searches and bounded read-only SQL analytics."""

from __future__ import annotations

import json
import re
import math
from datetime import date, datetime, time
from decimal import Decimal
from pathlib import Path

import duckdb
import lance
import pyarrow as pa

from snort.ingest.events import EVENT_COLUMNS
from snort.errors import RequestError
from snort.ingest.wal import WalReader
from snort.store.index import indexed_segments

BOUNDARY_RE = re.compile(r"[\s:;,=()\[\]{}\"']+")
EVENT_SCHEMA = pa.schema(
    [(c, pa.int64() if c == "source_seq" else pa.string()) for c in EVENT_COLUMNS]
)
RESULT_SCHEMA = pa.schema(
    list(EVENT_SCHEMA)
    + [
        pa.field("_row", pa.int64()),
        pa.field("_segment", pa.string()),
        pa.field("_source", pa.string()),
        pa.field("_search_mode", pa.string()),
        pa.field("_score", pa.float64()),
    ]
)
SELECT_RESULT = ", ".join(
    ["ts_original AS ts"]
    + EVENT_COLUMNS[1:]
    + ["_row", "_segment", "_source", "_search_mode", "_score"]
)


def json_value(value):
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (list, tuple)):
        return [json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): json_value(item) for key, item in value.items()}
    if isinstance(value, float) and not math.isfinite(value):
        raise RequestError("query produced a non-finite numeric result")
    return value


def unranked(rows):
    return [
        {key: value for key, value in row.items() if key != "_score"} for row in rows
    ]


def split_query(query):
    if not isinstance(query, str) or not query.strip():
        raise RequestError("search query must not be empty")
    parts = [p for p in BOUNDARY_RE.split(query.strip()) if p]
    if not parts:
        raise RequestError("query has no searchable parts")
    return sorted(parts, key=len, reverse=True)


def _duckdb_con():
    con = duckdb.connect(config={"TimeZone": "UTC"})
    try:
        con.execute("LOAD lance")
    except duckdb.Error:
        try:
            con.execute("INSTALL lance; LOAD lance")
        except Exception:
            con.close()
            raise
    return con


def _readonly_con():
    con = duckdb.connect(config={"memory_limit": "256MB", "threads": 2})
    try:
        # Initialize DuckDB's timezone extension before disabling extension/file
        # access. Only trusted setup SQL runs while external access is enabled.
        con.execute("SET TimeZone = 'UTC'")
        con.execute("SET enable_external_access = false")
        return con
    except Exception:
        con.close()
        raise


def _sealed_entries(sealed_dir):
    path = Path(sealed_dir) / "sealed-manifest.json"
    return json.loads(path.read_text())["segments"] if path.exists() else []


def _collect_wal_records(wal_dir, sealed_wal_names, query_str=None):
    records = []
    if not Path(wal_dir).exists():
        return records
    from snort.ingest.wal import _read_lines

    for path in WalReader(wal_dir).segment_paths():
        if path.name in sealed_wal_names:
            continue
        for row, line in enumerate(_read_lines(path)):
            if not line.strip():
                continue
            event = json.loads(line)["event"]
            if query_str is not None and query_str not in event["raw"]:
                continue
            records.append(
                dict(
                    event,
                    _row=row,
                    _segment=path.name,
                    _source="wal",
                    _search_mode="substring",
                    _score=0.5,
                )
            )
    return records


def _filter_rows(records, filter_expr=None, query=None, limit=1000):
    with _readonly_con() as con:
        con.register("events", pa.Table.from_pylist(records, schema=RESULT_SCHEMA))
        clauses, params = [], []
        if query is not None:
            clauses.append("contains(raw, ?)")
            params.append(query)
        if filter_expr:
            clauses.append(f"({filter_expr})")
        sql = (
            f"SELECT {SELECT_RESULT} FROM (SELECT * EXCLUDE(ts), ts AS ts_original, CAST(ts AS TIMESTAMPTZ) AS ts FROM events)"
            + (" WHERE " + " AND ".join(clauses) if clauses else "")
            + " LIMIT ?"
        )
        params.append(limit)
        try:
            statements = con.extract_statements(sql)
            if len(statements) != 1 or statements[0].type.name != "SELECT":
                raise RequestError("filter must be a single SQL expression")
            cursor = con.execute(sql, params)
            return [
                dict(zip([d[0] for d in cursor.description], row))
                for row in cursor.fetchall()
            ]
        except duckdb.Error as exc:
            raise RequestError(f"invalid filter: {exc}") from exc


def search_bm25(
    query, sealed_dir, index_dir=None, wal_dir=None, filter_expr=None, *, limit=1000
):
    return search(
        query,
        sealed_dir,
        index_dir,
        wal_dir,
        filter_expr=filter_expr,
        limit=limit,
        bm25=True,
    )


def search(
    query,
    sealed_dir,
    index_dir=None,
    wal_dir=None,
    *,
    limit=1000,
    bm25=False,
    filter_expr=None,
):
    split_query(query)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 10000:
        raise RequestError("limit must be between 1 and 10000")
    # Validate even on empty stores and never reinterpret malformed filters as no matches.
    _filter_rows([], filter_expr)
    query = query.strip()
    sealed_dir = Path(sealed_dir)
    sealed = _sealed_entries(sealed_dir)
    sealed_wal = {s["wal_segment"] for s in sealed}
    indexed = indexed_segments(Path(index_dir)) if index_dir is not None else {}
    wal_records = (
        _collect_wal_records(wal_dir, sealed_wal) if wal_dir is not None else []
    )
    if bm25:
        results = []
        for seg in sealed:
            ds = lance.dataset(str(sealed_dir / seg["name"]))
            has_fts = any(i.name == "raw_idx" for i in ds.describe_indices())
            if has_fts:
                # Filter through DuckDB below for identical SQL semantics on sealed/live data.
                table = ds.scanner(full_text_query=query, with_row_id=True).to_table()
                for row in table.to_pylist():
                    results.append(
                        dict(
                            {c: row[c] for c in EVENT_COLUMNS},
                            _row=int(row["_rowid"]),
                            _segment=seg["name"],
                            _source="index",
                            _search_mode="bm25",
                            _score=float(row["_score"]),
                        )
                    )
            else:
                for offset, event in enumerate(ds.to_table().to_pylist()):
                    if query in event["raw"]:
                        results.append(
                            dict(
                                event,
                                _row=offset,
                                _segment=seg["name"],
                                _source="scan",
                                _search_mode="substring-fallback",
                                _score=0.5,
                            )
                        )
        results.extend(r for r in wal_records if query in r["raw"])
        filtered = _filter_rows(results, filter_expr, limit=max(len(results), 1))
        filtered.sort(key=lambda r: (-r["_score"], r["event_hash"]))
        return filtered[:limit]

    if not sealed:
        return unranked(_filter_rows(wal_records, filter_expr, query, limit))
    # Keep the Lance/DuckDB unified scan; do not silently drop failed segments or predicates.
    try:
        con = _duckdb_con()
    except duckdb.Error:
        import logging

        logging.warning(
            "DuckDB Lance extension unavailable; using explicit Arrow scan fallback"
        )
        records = list(wal_records)
        for seg in sealed:
            ds = lance.dataset(str(sealed_dir / seg["name"]))
            records.extend(
                dict(
                    event,
                    _row=i,
                    _segment=seg["name"],
                    _source="scan",
                    _search_mode="arrow-substring-fallback",
                    _score=0.5,
                )
                for i, event in enumerate(ds.to_table().to_pylist())
            )
        return unranked(_filter_rows(records, filter_expr, query, limit))
    with con:
        con.register(
            "wal_buffer", pa.Table.from_pylist(wal_records, schema=RESULT_SCHEMA)
        )
        parts = ["SELECT * FROM wal_buffer"]
        for seg in sealed:
            path = str(sealed_dir / seg["name"]).replace("'", "''")
            name = seg["name"].replace("'", "''")
            source = "index" if seg["name"] in indexed else "scan"
            parts.append(
                f"SELECT {', '.join(EVENT_COLUMNS)}, row_number() OVER () - 1 AS _row, "
                f"'{name}' AS _segment, '{source}' AS _source, 'substring' AS _search_mode, 0.5 AS _score FROM '{path}'"
            )
        where = "contains(raw, ?)" + (f" AND ({filter_expr})" if filter_expr else "")
        sql = f"SELECT {SELECT_RESULT} FROM (SELECT * EXCLUDE(ts), ts AS ts_original, CAST(ts AS TIMESTAMPTZ) AS ts FROM ({' UNION ALL '.join(parts)})) WHERE {where} LIMIT ?"
        cursor = con.execute(sql, [query, limit])
        return unranked(
            [
                dict(zip([d[0] for d in cursor.description], row))
                for row in cursor.fetchall()
            ]
        )


def query_tables(sql, tables, *, limit=1000):
    """Read-only SQL on registered Arrow snapshots, without external file access."""
    if not isinstance(sql, str) or not sql.strip():
        raise RequestError("sql must be a nonempty SELECT query")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 10000:
        raise RequestError("limit must be between 1 and 10000")
    with _readonly_con() as con:
        for name, table in tables.items():
            con.register(name, table)
        try:
            statements = con.extract_statements(sql)
            if len(statements) != 1 or statements[0].type.name != "SELECT":
                raise RequestError("only one read-only SELECT statement is allowed")
            cursor = con.execute(
                f"SELECT * FROM ({sql.strip().rstrip(';')}) AS result LIMIT ?", [limit]
            )
            # Arrow uses standard timezone objects; DuckDB's Python row conversion
            # otherwise requires an undeclared pytz dependency for TIMESTAMPTZ.
            arrow = (
                cursor.to_arrow_table()
                if hasattr(cursor, "to_arrow_table")
                else cursor.fetch_arrow_table()
            )
            return [json_value(row) for row in arrow.to_pylist()]
        except duckdb.Error as exc:
            raise RequestError(f"invalid SQL query: {exc}") from exc
