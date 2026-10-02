"""Provenance joins: traces linked by shared entities within a time window."""

from __future__ import annotations


class ProvenanceGraph:
    """Minimal temporal entity graph: entity -> traces, plus trace windows."""

    def __init__(self, path_window_s: float = 900.0) -> None:
        self.path_window_s = path_window_s
        self._entity_traces: dict[str, set[str]] = {}
        self._trace_entities: dict[str, frozenset[str]] = {}
        self._trace_ts: dict[str, float] = {}

    def add_trace(
        self,
        trace_id: str,
        entities: frozenset[str],
        ts: float,
    ) -> None:
        old = self._trace_entities.get(trace_id)
        if old is not None:
            for ent in old:
                members = self._entity_traces.get(ent)
                if members is not None:
                    members.discard(trace_id)
        self._trace_entities[trace_id] = entities
        self._trace_ts[trace_id] = ts
        for ent in entities:
            self._entity_traces.setdefault(ent, set()).add(trace_id)

    def _in_window(self, a: str, b: str, within_s: float | None) -> bool:
        window = self.path_window_s if within_s is None else within_s
        return abs(self._trace_ts[a] - self._trace_ts[b]) <= window

    def has_path(self, a: str, b: str, within_s: float | None = None) -> bool:
        """True when a and b share an entity within the time window."""
        if a not in self._trace_entities or b not in self._trace_entities:
            return False
        if not self._in_window(a, b, within_s):
            return False
        return bool(self._trace_entities[a] & self._trace_entities[b])

    def related(
        self, trace_id: str, within_s: float | None = None
    ) -> dict[str, int]:
        """Return {trace_id: shared-entity count} within the time window."""
        if trace_id not in self._trace_entities:
            return {}
        out: dict[str, int] = {}
        for ent in self._trace_entities[trace_id]:
            for other in self._entity_traces.get(ent, ()):
                if other == trace_id or not self._in_window(trace_id, other, within_s):
                    continue
                out[other] = out.get(other, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: kv[1], reverse=True))
