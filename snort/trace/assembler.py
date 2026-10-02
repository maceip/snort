"""Trace assembler: groups events into open/sealed traces (plan sections 3-4.2).

Anchor rules (version 1):
- command/beacon trace: event carries ``session_id`` or ``beacon_id`` ->
  ``session:<host>:<id>`` (covers CTA beacon sessions / shell sessions).
- host trace: event carries ``session_root`` or ``root_pid`` ->
  ``host:<host>:<root>`` (process subtree under a session root; the first
  ancestor below a service boundary per the plan).
- fallback: ``host:<host>:<subject>`` where subject is the process/entity id,
  else ``host:<host>:default``.

Lifecycle: a trace seals after ``idle_timeout_s`` without events (via
: meth:`seal_idle`) or when an event would extend it past
``max_duration_s`` (rolling window with the same anchor). Later/out-of-order
arrivals widen the window and bump the version (versioned correction).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Mapping

from snort.trace.features import MergeableTraceFeatures


def anchor_for_event(event: Mapping) -> str:
    host = str(event.get("host", "unknown"))
    session = event.get("session_id", event.get("beacon_id"))
    if session is not None:
        return f"session:{host}:{session}"
    root = event.get("session_root", event.get("root_pid"))
    if root is not None:
        return f"host:{host}:{root}"
    subject = event.get("subject")
    if isinstance(subject, Mapping):
        subject = subject.get("id", subject.get("pid", "default"))
    if subject is None:
        subject = event.get("process_id", event.get("pid", "default"))
    return f"host:{host}:{subject}"


def event_hash_for(event: Mapping) -> str:
    if event.get("event_hash") is not None:
        return str(event["event_hash"])
    parts = [
        str(event.get("ts", "")),
        str(event.get("host", "")),
        str(event.get("source_id", "")),
        str(event.get("source_seq", "")),
        str(event.get("subject", "")),
        str(event.get("object", "")),
        str(event.get("action", "")),
        str(event.get("template_hash", "")),
        str(event.get("tokens", "")),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:32]


@dataclass
class Trace:
    trace_id: str
    anchor: str
    features: MergeableTraceFeatures = field(default_factory=MergeableTraceFeatures)
    member_event_hashes: list[str] = field(default_factory=list)
    state: str = "open"
    version: int = 0

    @property
    def event_count(self) -> int:
        return self.features.event_count

    @property
    def duration(self) -> float:
        return self.features.duration

    @property
    def start_ts(self) -> float | None:
        return self.features.start_ts

    @property
    def end_ts(self) -> float | None:
        return self.features.end_ts

    def add_event(self, event: Mapping) -> None:
        if self.state != "open":
            raise ValueError(f"trace {self.trace_id} is sealed")
        self.features.add_event(event=event)
        self.member_event_hashes.append(event_hash_for(event))
        self.version += 1

    def merge(self, other: "Trace") -> "Trace":
        """Combine two traces with the same anchor into a new sealed trace."""
        if self.anchor != other.anchor:
            raise ValueError("can only merge traces with the same anchor")
        merged = Trace(
            trace_id=f"{self.anchor}:merged",
            anchor=self.anchor,
            features=self.features.merge(other.features),
            member_event_hashes=self.member_event_hashes + other.member_event_hashes,
            state="sealed",
            version=self.version + other.version + 1,
        )
        return merged

    def seal(self) -> None:
        self.state = "sealed"
        self.version += 1

    def to_dict(self) -> dict:
        return {
            "trace_id": self.trace_id,
            "anchor": self.anchor,
            "features": self.features.to_dict(),
            "member_event_hashes": list(self.member_event_hashes),
            "state": self.state,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Trace":
        return cls(
            trace_id=d["trace_id"],
            anchor=d["anchor"],
            features=MergeableTraceFeatures.from_dict(d["features"]),
            member_event_hashes=list(d.get("member_event_hashes", [])),
            state=d.get("state", "open"),
            version=int(d.get("version", 0)),
        )


class TraceAssembler:
    """Incremental assembler: one open trace per anchor plus sealed history."""

    def __init__(
        self,
        idle_timeout_s: float = 30 * 60,
        max_duration_s: float = 24 * 3600,
        num_perm: int = 128,
    ):
        if idle_timeout_s <= 0 or max_duration_s <= 0:
            raise ValueError("timeouts must be positive")
        self.idle_timeout_s = idle_timeout_s
        self.max_duration_s = max_duration_s
        self.num_perm = num_perm
        self._open: dict[str, Trace] = {}
        self._sealed: list[Trace] = []
        self._anchor_counts: dict[str, int] = {}

    def _new_trace(self, anchor: str) -> Trace:
        idx = self._anchor_counts.get(anchor, 0)
        self._anchor_counts[anchor] = idx + 1
        trace = Trace(
            trace_id=f"{anchor}:{idx}",
            anchor=anchor,
            features=MergeableTraceFeatures(num_perm=self.num_perm),
        )
        self._open[anchor] = trace
        return trace

    def ingest(self, event: Mapping) -> Trace:
        """Add an event; returns the trace it landed in (seals rolled windows)."""
        if "ts" not in event:
            raise KeyError("event missing required 'ts'")
        anchor = anchor_for_event(event)
        trace = self._open.get(anchor)
        if trace is None:
            trace = self._new_trace(anchor)
            trace.add_event(event)
            return trace
        ts = float(event["ts"])
        start = trace.start_ts if trace.start_ts is not None else ts
        window_start = min(start, ts)
        last = trace.end_ts if trace.end_ts is not None else ts
        idle_gap = ts - last if ts >= last else 0.0
        if idle_gap > self.idle_timeout_s or (ts - window_start) > self.max_duration_s:
            trace.seal()
            self._sealed.append(trace)
            trace = self._new_trace(anchor)
        trace.add_event(event)
        return trace

    def seal_idle(self, now: float) -> list[Trace]:
        """Seal open traces idle longer than the timeout. Returns newly sealed."""
        newly: list[Trace] = []
        for anchor, trace in list(self._open.items()):
            last = trace.end_ts if trace.end_ts is not None else now
            if float(now) - float(last) > self.idle_timeout_s:
                trace.seal()
                newly.append(trace)
                del self._open[anchor]
                self._sealed.append(trace)
        return newly

    def merge_traces(self, first_id: str, second_id: str) -> Trace:
        first = self.get(first_id)
        second = self.get(second_id)
        if first is None or second is None:
            raise KeyError("unknown trace id")
        return first.merge(second)

    def get(self, trace_id: str) -> Trace | None:
        for trace in self._open.values():
            if trace.trace_id == trace_id:
                return trace
        for trace in self._sealed:
            if trace.trace_id == trace_id:
                return trace
        return None

    @property
    def open_traces(self) -> list[Trace]:
        return list(self._open.values())

    @property
    def sealed_traces(self) -> list[Trace]:
        return list(self._sealed)

    def all_traces(self) -> list[Trace]:
        return self.open_traces + self.sealed_traces


# --- Batch builders for converters and go/no-go tests (from convert slice) ---
SERVICE_BOUNDARY_NAMES = frozenset(
    {
        # Linux service / session boundaries (CADETS is FreeBSD/Linux)
        "sshd",
        "sshd:",
        "systemd",
        "init",
        "launchd",
        "login",
        "getty",
        "cron",
        "nginx",
        # Windows boundaries (kept for OpTC / version 2 reuse)
        "winlogon.exe",
        "services.exe",
        "explorer.exe",
        "svchost.exe",
        # interactive hosts that delimit sessions
        "chrome",
        "firefox",
    }
)


def session_root(pid: str, parent_of: dict, image_of: dict) -> str:
    """Walk ancestry until the parent is a service boundary or missing."""
    seen = set()
    cur = pid
    while cur is not None and cur not in seen:
        seen.add(cur)
        parent = parent_of.get(cur)
        if parent is None:
            return cur
        if str(image_of.get(parent, "")).lower() in SERVICE_BOUNDARY_NAMES:
            return cur
        cur = parent
    return cur if cur is not None else pid


def build_process_subtree_traces(
    events, parent_of: dict | None = None, image_of: dict | None = None
):
    """Assign each event to (host, session-root) and aggregate trace rows.

    events: DataFrame with at least [event_hash, host, subject, ts, action,
        object]. parent_of maps process id -> parent process id; when absent
    each subject is its own root (documented fallback for exports without
        ancestry).
    Returns a DataFrame with TRACE_COLUMNS-compatible rows.
    """
    import pandas as pd

    parent_of = parent_of or {}
    image_of = image_of or {}
    rows = []
    grouped: dict[tuple, list] = {}
    for rec in events.to_dict("records"):
        root = session_root(str(rec["subject"]), parent_of, image_of)
        grouped.setdefault((str(rec["host"]), root), []).append(rec)
    for (host, root), members in grouped.items():
        members.sort(key=lambda r: (int(r["ts"]), str(r["event_hash"])))
        toks = [
            f"{m['action']}::{str(m['object']).split('/')[-1].split(chr(92))[-1][:48]}"
            for m in members
        ]
        import json as _json

        rows.append(
            {
                "trace_id": f"{host}::{root}",
                "anchor": root,
                "host": host,
                "t_start": int(members[0]["ts"]),
                "t_end": int(members[-1]["ts"]),
                "member_count": len(members),
                "text": " ".join(toks),
                "event_hashes": _json.dumps([m["event_hash"] for m in members]),
            }
        )
    out = pd.DataFrame(rows)
    return out.sort_values("trace_id").reset_index(drop=True)


def build_beacon_traces(events, session_col: str = "subject", text_col: str = "raw_text"):
    """One trace per beacon session id (CTA version-1 rule).

    text_col names an optional extra events column carrying the full command
    text; when absent the trace text falls back to action/object tokens.
    """
    import pandas as pd
    import json as _json

    rows = []
    for anchor, grp in events.groupby(session_col):
        members = grp.sort_values(["ts", "event_hash"]).to_dict("records")
        host = str(members[0]["host"])
        if text_col in grp.columns:
            text = " ".join(str(m[text_col]) for m in members)
        else:
            text = " ".join(f"{m['action']}::{m['object']}" for m in members)
        rows.append(
            {
                "trace_id": f"{host}::{anchor}",
                "anchor": str(anchor),
                "host": host,
                "t_start": int(members[0]["ts"]),
                "t_end": int(members[-1]["ts"]),
                "member_count": len(members),
                "text": text,
                "event_hashes": _json.dumps([m["event_hash"] for m in members]),
            }
        )
    out = pd.DataFrame(rows)
    return out.sort_values("trace_id").reset_index(drop=True)
