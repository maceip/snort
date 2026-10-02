"""Exact indicator index with posting caps and common-key skip (plan 4.2/4.3)."""

from __future__ import annotations

import math
from collections import deque


class IndicatorIndex:
    """indicator key -> most-recent trace ids (cap per posting list)."""

    def __init__(self, posting_cap: int = 10_000) -> None:
        self.posting_cap = posting_cap
        self._postings: dict[str, deque[str]] = {}
        self._trace_keys: dict[str, frozenset[str]] = {}
        self.num_traces = 0

    def add(self, trace_id: str, indicators: frozenset[str]) -> None:
        if trace_id not in self._trace_keys:
            self.num_traces += 1
        else:
            for key in self._trace_keys[trace_id]:
                posting = self._postings.get(key)
                if posting is not None:
                    try:
                        posting.remove(trace_id)
                    except ValueError:
                        pass
        self._trace_keys[trace_id] = indicators
        for key in indicators:
            posting = self._postings.setdefault(key, deque())
            posting.append(trace_id)
            while len(posting) > self.posting_cap:
                posting.popleft()

    def doc_freq(self, key: str) -> int:
        return len(self._postings.get(key, ()))

    def is_too_common(self, key: str) -> bool:
        """Skip keys in more than max(100, 0.1% of indexed traces)."""
        limit = max(100, 0.001 * self.num_traces)
        return self.doc_freq(key) > limit

    def idf(self, key: str) -> float:
        return math.log((self.num_traces + 1) / (self.doc_freq(key) + 1)) + 1.0

    def query(
        self, indicators: frozenset[str], exclude: str | None = None
    ) -> dict[str, int]:
        """Return {trace_id: shared rare-indicator count}, common keys skipped."""
        shared: dict[str, int] = {}
        for key in indicators:
            if self.is_too_common(key):
                continue
            for tid in self._postings.get(key, ()):
                if tid == exclude:
                    continue
                shared[tid] = shared.get(tid, 0) + 1
        # Most-recent-first ordering is inherited from posting order on ties.
        return dict(sorted(shared.items(), key=lambda kv: kv[1], reverse=True))

    def idf_shared_weight(self, a: frozenset[str], b: frozenset[str]) -> float:
        shared = a & b
        if not shared:
            return 0.0
        return sum(0.0 if self.is_too_common(k) else self.idf(k) for k in shared)
