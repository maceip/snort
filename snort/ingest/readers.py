"""Version 1 readers: E3-CADETS exports and the CTA corpus (plan section 4.1).

Both datasets are structured, so version 1 needs no Drain/LogCrisp
templates: the readers below accept the databases' own exports plus a
generic JSONL reader. Each reader yields raw mappings; the caller
normalizes them with :func:`snort.ingest.events.normalize_event`.

Per-source sequence numbers are stamped here when missing (plan
section 3, ordering). The counter is local to a single reader
invocation and restarts at zero on the next invocation, so it orders
events *within* a run only.

It is not a resume mechanism: re-reading the same file restamps the
same sequence numbers. Re-ingestion is made safe downstream instead,
where :class:`snort.runtime.LiveRuntime` records content and sequence
identities plus ``source_checkpoints`` and reports repeated events as
duplicates. Callers that need cross-run ordering should supply
``source_id``/``source_seq`` or ``event_id`` themselves.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path


def _stamp_seq(records, default_source: str):
    counters: dict[str, int] = defaultdict(int)
    for record in records:
        if not isinstance(record, dict):
            raise ValueError(f"reader record must be a mapping: {record!r}")
        record = dict(record)
        record.setdefault("source_id", default_source)
        source = str(record["source_id"])
        if "source_seq" not in record or record["source_seq"] is None:
            record["source_seq"] = counters[source]
        counters[source] = int(record["source_seq"]) + 1
        yield record


def iter_jsonl(path: str | Path, *, source_id: str = "generic"):
    """Yield raw records from a JSONL file (one JSON object per line)."""
    with open(path, "r", encoding="utf-8") as fh:
        def gen():
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
        yield from _stamp_seq(gen(), source_id)


def iter_e3_jsonl(path: str | Path):
    """Yield raw records from an E3-CADETS export.

    Accepts the PIDSMaker converter output shape: JSONL rows with at
    least ``ts``/``timestamp``, ``host``, subject/object/action fields.
    Common CDM export aliases (``timestamp``, ``src``, ``dst``,
    ``event_type``) are mapped to the Event schema keys.
    """
    def gen():
        for record in iter_jsonl(path, source_id="e3-cadets"):
            record = dict(record)
            record.setdefault("ts", record.pop("timestamp", None))
            record.setdefault("host", record.pop("hostname", None))
            record.setdefault("subject", record.pop("src", record.get("subject", "")))
            record.setdefault("object", record.pop("dst", record.get("object", "")))
            record.setdefault("action", record.pop("event_type", record.get("action", "")))
            yield record
    yield from gen()


def iter_cta_json(path: str | Path):
    """Yield raw records from the Unveiling-CTAs corpus file.

    Accepts either a JSON array of beacon sessions or JSONL with one
    session per line. Each session has a session/beacon id, an actor
    label, timestamps and a list of commands; each command becomes one
    raw event with the session as its subject so command traces stay
    joinable (plan section 4.2, command trace).
    """
    text = Path(path).read_text(encoding="utf-8").strip()
    if not text:
        return
    if text.startswith("["):
        sessions = json.loads(text)
    else:
        sessions = [json.loads(line) for line in text.splitlines() if line.strip()]

    def gen():
        for session in sessions:
            if not isinstance(session, dict):
                raise ValueError(f"CTA session must be a mapping: {session!r}")
            session_id = session.get("session_id", session.get("beacon_id", session.get("id", "")))
            actor = session.get("actor", session.get("actor_id", "unknown"))
            host = session.get("host", f"cta-{actor}")
            commands = session.get("commands", session.get("events", []))
            if isinstance(commands, str):
                commands = [commands]
            for command in commands:
                if isinstance(command, dict):
                    ts = command.get("ts", command.get("timestamp", session.get("ts", session.get("timestamp", ""))))
                    cmd_text = command.get("command", command.get("text", command.get("raw", "")))
                    tactic = command.get("tactic", command.get("technique", ""))
                else:
                    ts = session.get("ts", session.get("timestamp", ""))
                    cmd_text = command
                    tactic = ""
                if not ts:
                    raise ValueError(f"CTA command has no timestamp: {session!r}")
                yield {
                    "ts": ts,
                    "host": host,
                    "source_id": "cta",
                    "subject": str(session_id),
                    "object": str(cmd_text),
                    "object_class": "command",
                    "action": "exec",
                    "attributes": {"actor": actor, "tactic": tactic},
                    "raw": str(cmd_text),
                }
    yield from _stamp_seq(gen(), "cta")
