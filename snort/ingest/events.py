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

import collections
import json
import math
import re
import zlib
from datetime import datetime, timezone

import blake3 as _blake3

HASH_ALGO = "blake3-256"

# FluxSieve 32-bit bitmask tags (plan/research enhancement 1)
FLUX_TAG_ERROR = 1 << 0  # 0x01
FLUX_TAG_ATTACK = 1 << 1  # 0x02
FLUX_TAG_NETWORK = 1 << 2  # 0x04
FLUX_TAG_FILE_MOD = 1 << 3  # 0x08
FLUX_TAG_AUTH = 1 << 4  # 0x10
FLUX_TAG_AI = 1 << 5  # 0x20
FLUX_TAG_ANOMALY = 1 << 6  # 0x40

# SCLC normalization regexes (Unveiling-CTAs enhancement 7)
_SCLC_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")
_SCLC_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)
_SCLC_WINPATH_RE = re.compile(
    r"(?:[a-zA-Z]:|%[A-Z_]+%|\\[a-zA-Z0-9_$.-]+)(?:\\[a-zA-Z0-9_$. -]+)+", re.I
)
_SCLC_UNIXPATH_RE = re.compile(
    r"(?:/(?:bin|usr|etc|var|tmp|home|opt|dev|proc|sys)[^\s'\"<>]*)", re.I
)
_SCLC_REG_RE = re.compile(r"HKEY_[A-Z_]+(?:\\[a-zA-Z0-9_$. -]+)+", re.I)
_SCLC_HASH_RE = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
_SCLC_GUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)

_ERR_WORDS = {"error", "err", "fail", "failed", "panic", "fatal", "exception", "stderr"}
_ATTACK_WORDS = {
    "powershell",
    "certutil",
    "whoami",
    "net user",
    "mimikatz",
    "vssadmin",
    "bcp",
    "curl",
    "wget",
    "chmod +x",
    "nc -e",
    "bash -i",
    "reg add",
    "rundll32",
    "wmic",
    "mshta",
    "cscript",
    "wscript",
    "cmd.exe",
}
_NET_ACTIONS = {
    "connect",
    "accept",
    "send",
    "recv",
    "bind",
    "listen",
    "socket",
    "http",
    "dns",
}
_FILE_ACTIONS = {
    "write",
    "unlink",
    "rename",
    "modify",
    "chmod",
    "chown",
    "create",
    "delete",
}
_AUTH_WORDS = {
    "login",
    "auth",
    "token",
    "password",
    "credential",
    "sudo",
    "su",
    "privilege",
}


def normalize_sclc(text: str) -> str:
    """Normalize raw command text using SCLC semantic abstractions (Unveiling-CTAs)."""
    if not text:
        return ""
    s = _SCLC_URL_RE.sub("<URL>", text)
    s = _SCLC_IP_RE.sub("<IP>", s)
    s = _SCLC_GUID_RE.sub("<GUID>", s)
    s = _SCLC_HASH_RE.sub("<HASH>", s)
    s = _SCLC_REG_RE.sub("<REG_KEY>", s)
    s = _SCLC_WINPATH_RE.sub("<FILE_PATH>", s)
    s = _SCLC_UNIXPATH_RE.sub("<FILE_PATH>", s)
    return s


def compute_byte_entropy(data: bytes) -> float:
    """Shannon byte entropy H(B) = -sum(p * log2(p)) over raw byte chunks (CLAD)."""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    ent = 0.0
    for count in counts.values():
        p = count / total
        ent -= p * math.log2(p)
    return ent


def compute_compression_deviation(data: bytes) -> tuple[float, float, bool]:
    """Calculate (entropy, compression_ratio, is_anomalous) directly on bytes (CLAD)."""
    if len(data) < 16:
        return 0.0, 1.0, False
    ent = compute_byte_entropy(data)
    compressed = zlib.compress(data, level=1)
    comp_ratio = len(compressed) / len(data)
    is_anomaly = ent > 7.1 and comp_ratio > 0.92
    return ent, comp_ratio, is_anomaly


def compute_flux_tags(
    action: str, raw_text: str, attributes: dict, anomaly: bool = False
) -> int:
    """Single-pass bitmask computation over incoming records (FluxSieve)."""
    tags = 0
    act_lower = str(action).lower()
    text_lower = str(raw_text).lower()

    if any(w in act_lower or w in text_lower for w in _ERR_WORDS) or str(
        attributes.get("status", "")
    ).lower() in ("error", "fail"):
        tags |= FLUX_TAG_ERROR
    if (
        any(w in text_lower for w in _ATTACK_WORDS)
        or attributes.get("technique_ids")
        or attributes.get("techniques")
    ):
        tags |= FLUX_TAG_ATTACK
    if (
        any(act in act_lower for act in _NET_ACTIONS)
        or "net" in act_lower
        or attributes.get("remote_ip")
        or attributes.get("port")
    ):
        tags |= FLUX_TAG_NETWORK
    if any(act in act_lower for act in _FILE_ACTIONS) or "file_write" in act_lower:
        tags |= FLUX_TAG_FILE_MOD
    if any(w in act_lower or w in text_lower for w in _AUTH_WORDS):
        tags |= FLUX_TAG_AUTH
    if (
        any(k.startswith("gen_ai.") or k.startswith("ai.") for k in attributes)
        or "model" in attributes
        or "prompt_tokens" in attributes
    ):
        tags |= FLUX_TAG_AI
    if anomaly or float(attributes.get("anomaly_score", 0.0)) > 0.5:
        tags |= FLUX_TAG_ANOMALY
    return tags


# Columns of the sealed Parquet segments (plan section 4.1).
EVENT_COLUMNS = [
    "ts",
    "host",
    "source_id",
    "source_seq",
    "ingest_ts",
    "event_hash",
    "template_hash",
    "flux_tags",
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

    # SCLC command normalization (Unveiling-CTAs)
    raw_str = str(raw.get("raw", ""))
    sclc_template = normalize_sclc(template_text)

    # CLAD byte entropy & compression deviation check (CLAD)
    raw_bytes = (raw_str or _dump(raw)).encode("utf-8")
    ent, comp_ratio, is_anom = compute_compression_deviation(raw_bytes)
    if is_anom:
        attributes["anomaly_score"] = max(
            float(attributes.get("anomaly_score", 0.0)), 0.85
        )
        attributes["byte_entropy"] = round(ent, 3)
        attributes["compression_ratio"] = round(comp_ratio, 3)

    # FluxSieve bitmask tags computation (FluxSieve)
    flux_tags = compute_flux_tags(
        str(raw["action"]), raw_str, attributes, anomaly=is_anom
    )
    attributes["flux_tags"] = flux_tags

    event = {
        "ts": _coerce_ts(raw["ts"]),
        "host": str(raw["host"]),
        "source_id": str(raw.get("source_id", source_id)),
        "source_seq": int(seq),
        "ingest_ts": ingest_ts or str(raw.get("ingest_ts", "")) or _now_iso(),
        "event_hash": "",
        "template_hash": template_hash(
            str(raw["action"]), str(object_class), sclc_template
        ),
        "flux_tags": int(flux_tags),
        "subject": _dump(subject),
        "object": _dump(obj),
        "action": str(raw["action"]),
        "attributes": _dump(attributes),
        "raw": raw_str or _dump(raw),
    }
    event["event_hash"] = event_hash(event)
    return event
