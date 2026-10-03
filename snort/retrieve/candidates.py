"""Union candidate retrieval capped at 50 (plan section 4.3, version 1)."""

from __future__ import annotations

import math
from dataclasses import dataclass

from snort.retrieve.indicators import IndicatorIndex
from snort.retrieve.minhash_lsh import MinHashLSHIndex
from snort.retrieve.provenance import ProvenanceGraph
from snort.trace.signatures import Trace

MAX_CANDIDATES = 50


class ANNBlocker:
    """Experimental exact cosine scan over continuous candidate features.

    Inspired by BlockingPy; this helper does not build an approximate index.
    """

    def __init__(self, top_k: int = 20) -> None:
        self.top_k = top_k
        self._vectors: dict[str, list[float]] = {}

    def add(self, trace_id: str, vector: list[float]) -> None:
        self._vectors[trace_id] = vector

    def query(
        self, vector: list[float], exclude: str | None = None
    ) -> list[tuple[str, float]]:
        if not self._vectors or not vector:
            return []
        v_norm = math.sqrt(sum(x * x for x in vector)) or 1.0
        results: list[tuple[str, float]] = []
        for tid, other_v in self._vectors.items():
            if tid == exclude or len(other_v) != len(vector):
                continue
            o_norm = math.sqrt(sum(x * x for x in other_v)) or 1.0
            dot = sum(a * b for a, b in zip(vector, other_v))
            cos_sim = max(0.0, dot / (v_norm * o_norm))
            if cos_sim >= 0.5:
                results.append((tid, cos_sim))
        results.sort(key=lambda kv: (-kv[1], kv[0]))
        return results[: self.top_k]


@dataclass
class Candidate:
    trace_id: str
    sources: frozenset[str]
    estimate: float


class CandidateRetriever:
    """Union of LSH, indicator, provenance, and ANN sources, deduplicated, capped."""

    def __init__(
        self,
        lsh: MinHashLSHIndex,
        indicators: IndicatorIndex,
        provenance: ProvenanceGraph,
        ann: ANNBlocker | None = None,
        max_candidates: int = MAX_CANDIDATES,
    ) -> None:
        self.lsh = lsh
        self.indicators = indicators
        self.provenance = provenance
        self.ann = ann if ann is not None else ANNBlocker()
        self.max_candidates = max_candidates

    def _extract_dense_vector(self, trace: Trace) -> list[float]:
        dur = max(0.0, float(trace.end_ts) - float(trace.start_ts))
        tok_len = float(len(trace.tokens)) if hasattr(trace, "tokens") else 0.0
        ind_len = float(len(trace.indicators)) if hasattr(trace, "indicators") else 0.0
        ent_len = float(len(trace.entities)) if hasattr(trace, "entities") else 0.0
        return [dur, math.log1p(tok_len), math.log1p(ind_len), math.log1p(ent_len)]

    def index_trace(self, trace: Trace) -> None:
        self.lsh.insert(trace.trace_id, trace.signature)
        self.indicators.add(trace.trace_id, trace.indicators)
        self.provenance.add_trace(trace.trace_id, trace.entities, trace.start_ts)
        self.ann.add(trace.trace_id, self._extract_dense_vector(trace))

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
        for tid, sim in self.ann.query(
            self._extract_dense_vector(trace), exclude=trace.trace_id
        ):
            note(tid, "ann", sim)

        ranked = sorted(estimates, key=lambda t: (-estimates[t], t))
        return [
            Candidate(
                trace_id=tid,
                sources=frozenset(sources[tid]),
                estimate=estimates[tid],
            )
            for tid in ranked[: self.max_candidates]
        ]
