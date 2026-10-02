"""Shared Event Parquet schema (plan secs 3, 4.1).

One row per normalized event. Column order and types are fixed here so every
converter and every downstream stage agrees on the contract.
"""

from __future__ import annotations

import hashlib
import json
import re

EVENT_COLUMNS: dict[str, str] = {
    "ts": "int64",          # event time, nanoseconds since epoch
    "host": "string",       # reporting host / sensor
    "source_id": "string",  # which input produced this row (e.g. "e3-cadets")
    "source_seq": "int64",  # per-source sequence number, ordered by (ts)
    "ingest_ts": "int64",   # ingest time, ns; replay sets this equal to ts
    "subject": "string",    # acting entity id (process / session)
    "object": "string",     # target entity id (process / file / socket)
    "action": "string",     # edge type / command type
    "template_hash": "string",  # sha256 of the normalized template text
    "event_hash": "string",     # sha256 over the canonical event fields
    "raw": "string",        # original record, JSON-encoded
}

TRACE_COLUMNS: dict[str, str] = {
    "trace_id": "string",
    "anchor": "string",     # session root (E3) or beacon session id (CTA)
    "host": "string",
    "t_start": "int64",
    "t_end": "int64",
    "member_count": "int64",
    "text": "string",       # space-joined token stream for features
    "event_hashes": "string",  # JSON list of member event hashes
}

_WS = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    return _WS.sub(" ", (text or "").strip().lower())


def template_hash_for_text(text: str) -> str:
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()[:32]


def canonical_event_hash(
    ts: int, host: str, source_id: str, source_seq: int,
    subject: str, object_: str, action: str, template_hash: str,
) -> str:
    body = "\x00".join(
        str(v) for v in (ts, host, source_id, source_seq, subject, object_, action, template_hash)
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:32]


def to_parquet(df, path: str) -> None:
    import pyarrow as pa
    import pyarrow.parquet as pq

    for col, dtype in (EVENT_COLUMNS if "event_hash" in df.columns else TRACE_COLUMNS).items():
        if col not in df.columns:
            raise ValueError(f"missing required column: {col}")
    table = pa.Table.from_pandas(df, preserve_index=False)
    pq.write_table(table, path)


def read_parquet(path: str):
    import pandas as pd

    return pd.read_parquet(path)


def dump_json(obj, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")


def load_json(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)
