"""Event normalization and content hashing.

Every event that enters the pipeline is normalized to the Event schema
(plan section 3, core records) and given two stable content hashes:

- ``event_hash``: BLAKE3 over the canonical bytes of the event identity
  and payload. Appended to the WAL envelope and stored in Parquet.
- ``template_hash``: BLAKE3 over the normalized template text (action plus
  object class plus template string). Stable across batches, unlike
  LogCrisp's per-batch template IDs (plan decision 6).
"""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone

import blake3 as _blake3

HASH_ALGO = "blake3-256"

# Columns of the sealed Parquet segments (plan section 4.1).
EVENT_COLUMNS = [
    "ts",
    "host",
    "source_id",
    "source_seq",
    "ingest_ts",
    "event_hash",
    "template_hash",
    "subject",
    "object",
    "action",
    "attributes",
    "raw",
]


def hash_bytes(data: bytes) -> str:
    """BLAKE3-256 hex digest of raw bytes."""
    return _blake3.blake3(data).hexdigest()


def canonical_bytes(payload: object) -> bytes:
    """Canonical JSON bytes: sorted keys, compact separators, UTF-8."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def template_hash(action: str, object_class: str, template: str) -> str:
    """Stable content hash identifying a template (plan decision 6)."""
    normalized = "|".join(
        [
            action.strip().lower(),
            object_class.strip().lower(),
            " ".join(template.split()),
        ]
    )
    return hash_bytes(normalized.encode("utf-8"))


def event_hash(event: dict) -> str:
    """Content hash of a normalized event (without its own hash fields)."""
    body = {
        k: event.get(k)
        for k in (
            "ts",
            "host",
            "source_id",
            "source_seq",
            "subject",
            "object",
            "action",
            "attributes",
            "template_hash",
            "raw",
        )
    }
    return hash_bytes(canonical_bytes(body))


def _coerce_ts(value: object) -> str:
    if isinstance(value, (int, float)):
        if not math.isfinite(value):
            raise ValueError("event ts must be finite")
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("event ts is empty")
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("event ts must include a timezone")
        return text
    raise ValueError(f"unsupported ts value: {value!r}")


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _dump(value: object) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def normalize_event(
    raw: dict, *, source_id: str = "", ingest_ts: str | None = None
) -> dict:
    """Normalize one raw record to the Event schema.

    Required keys: ``ts``, ``host``, ``action``. ``source_id`` and
    ``source_seq`` fall back to the caller's source and 0; readers stamp
    per-source sequence numbers before calling this. Returns a new dict
    with exactly the EVENT_COLUMNS keys.
    """
    if not isinstance(raw, dict):
        raise ValueError(f"event must be a mapping, got {type(raw).__name__}")
    for key in ("ts", "host", "action"):
        if (
            key not in raw
            or raw[key] is None
            or (isinstance(raw[key], str) and not raw[key].strip())
        ):
            raise ValueError(f"event is missing required field {key!r}: {raw!r}")

    subject = raw.get("subject", "")
    obj = raw.get("object", "")
    object_class = raw.get("object_class", "")
    if not object_class and isinstance(obj, str):
        object_class = obj.split(":")[0] if ":" in obj else "entity"
    template_text = str(
        raw.get("template", raw.get("raw", f"{raw.get('action')} {obj}"))
    )
    attributes = raw.get("attributes", {})
    if attributes is None:
        attributes = {}
    if not isinstance(attributes, dict):
        raise ValueError(f"event attributes must be a mapping: {attributes!r}")
    attributes = dict(attributes)
    for key in (
        "session_id",
        "beacon_id",
        "session_root",
        "root_pid",
        "tokens",
        "technique_ids",
        "techniques",
        "indicators",
        "entities",
        "event_id",
    ):
        if key in raw:
            attributes[key] = raw[key]
    seq = raw.get("source_seq", 0)
    if isinstance(seq, bool) or not 0 <= int(seq) < 2**63 or str(int(seq)) != str(seq):
        raise ValueError("source_seq must be an integer between 0 and 2**63-1")

    event = {
        "ts": _coerce_ts(raw["ts"]),
        "host": str(raw["host"]),
        "source_id": str(raw.get("source_id", source_id)),
        "source_seq": int(seq),
        "ingest_ts": ingest_ts or str(raw.get("ingest_ts", "")) or _now_iso(),
        "event_hash": "",
        "template_hash": template_hash(
            str(raw["action"]), str(object_class), template_text
        ),
        "subject": _dump(subject),
        "object": _dump(obj),
        "action": str(raw["action"]),
        "attributes": _dump(attributes),
        "raw": str(raw.get("raw", "")) or _dump(raw),
    }
    event["event_hash"] = event_hash(event)
    return event
