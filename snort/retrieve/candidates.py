"""Union candidate retrieval capped at 50 (plan section 4.3, version 1)."""

from __future__ import annotations

from dataclasses import dataclass

from snort.retrieve.indicators import IndicatorIndex
from snort.retrieve.minhash_lsh import MinHashLSHIndex
from snort.retrieve.provenance import ProvenanceGraph
from snort.trace.signatures import Trace

MAX_CANDIDATES = 50


@dataclass
class Candidate:
    trace_id: str
    sources: frozenset[str]
    estimate: float


class CandidateRetriever:
    """Union of LSH, indicator, and provenance sources, deduplicated, capped."""

    def __init__(
        self,
        lsh: MinHashLSHIndex,
        indicators: IndicatorIndex,
        provenance: ProvenanceGraph,
        max_candidates: int = MAX_CANDIDATES,
    ) -> None:
        self.lsh = lsh
        self.indicators = indicators
        self.provenance = provenance
        self.max_candidates = max_candidates

    def index_trace(self, trace: Trace) -> None:
        self.lsh.insert(trace.trace_id, trace.signature)
        self.indicators.add(trace.trace_id, trace.indicators)
        self.provenance.add_trace(trace.trace_id, trace.entities, trace.start_ts)

    def retrieve(self, trace: Trace) -> list[Candidate]:
        estimates: dict[str, float] = {}
        sources: dict[str, set[str]] = {}

        def note(tid: str, source: str, score: float) -> None:
            if tid == trace.trace_id:
                return
            sources.setdefault(tid, set()).add(source)
            if score > estimates.get(tid, 0.0):
                estimates[tid] = score

        for tid, est in self.lsh.query(trace.signature, exclude=trace.trace_id):
            note(tid, "lsh", est)
        for tid, count in self.indicators.query(
            trace.indicators, exclude=trace.trace_id
        ).items():
            denom = max(len(trace.indicators), 1)
            note(tid, "indicator", min(1.0, count / denom))
        for tid, count in self.provenance.related(trace.trace_id).items():
            denom = max(len(trace.entities), 1)
            note(tid, "provenance", min(1.0, 0.5 + 0.5 * count / denom))

        ranked = sorted(estimates, key=lambda t: estimates[t], reverse=True)
        return [
            Candidate(
                trace_id=tid,
                sources=frozenset(sources[tid]),
                estimate=estimates[tid],
            )
            for tid in ranked[: self.max_candidates]
        ]
