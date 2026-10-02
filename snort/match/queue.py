"""Best-first progressive scoring queue under a comparison budget (plan 4.4).

Each trace's candidates are scored in order of estimated similarity; work
is charged in comparison cost (sequence cells + fixed model cost) against
a per-round allowance. Pairs over the wall-clock cap are scored without
sequence features and flagged as degraded.
"""

from __future__ import annotations

import heapq
import time
from dataclasses import dataclass, field

from snort.match.features import FEATURE_NAMES
from snort.match.pair_model import CalibratedPairModel
from snort.trace.signatures import Trace

SEQ_FEATURES = {"minhash_jaccard"}
SEQ_IDX = tuple(i for i, n in enumerate(FEATURE_NAMES) if n in SEQ_FEATURES)


@dataclass(order=True)
class _Queued:
    neg_estimate: float
    seq: int
    trace_id: str = field(compare=False)
    candidate_id: str = field(compare=False)
    cost: float = field(compare=False)


@dataclass
class ScoredPair:
    trace_id: str
    candidate_id: str
    estimate: float
    probability: float
    degraded: bool


class BestFirstQueue:
    """Max-estimate-first queue with a per-round cost budget."""

    def __init__(self, budget_per_round: float = 20_000.0) -> None:
        self.budget_per_round = budget_per_round
        self._heap: list[_Queued] = []
        self._seq = 0

    def __len__(self) -> int:
        return len(self._heap)

    def push(
        self, trace_id: str, candidate_id: str, estimate: float, cost: float = 1.0
    ) -> None:
        if cost <= 0:
            raise ValueError("cost must be positive")
        heapq.heappush(
            self._heap,
            _Queued(-estimate, self._seq, trace_id, candidate_id, cost),
        )
        self._seq += 1

    def pop_round(self) -> list[tuple[str, str, float]]:
        """Pop highest-estimate-first items fitting this round's budget."""
        out: list[tuple[str, str, float]] = []
        spent = 0.0
        # A single pair larger than the whole budget still makes progress:
        # the head of the queue is always popped at least once.
        while self._heap and (
            spent + self._heap[0].cost <= self.budget_per_round or not out
        ):
            item = heapq.heappop(self._heap)
            out.append((item.trace_id, item.candidate_id, -item.neg_estimate))
            spent += item.cost
        return out


def score_with_budget(
    jobs: list[tuple[Trace, Trace, list[float], float]],
    model: CalibratedPairModel,
    wall_cap_s: float = 0.002,
) -> list[ScoredPair]:
    """Score (trace, candidate, features, estimate) jobs in given order.

    Each pair gets a wall-clock cap; pairs over the cap are re-scored with
    sequence features zeroed and flagged degraded.
    """
    out: list[ScoredPair] = []
    for trace, cand, feats, estimate in jobs:
        start = time.perf_counter()
        proba = float(model.predict_proba([feats])[0])
        elapsed = time.perf_counter() - start
        degraded = False
        if elapsed > wall_cap_s:
            degraded = True
            lite = list(feats)
            for i in SEQ_IDX:
                lite[i] = 0.0
            proba = float(model.predict_proba([lite])[0])
        out.append(
            ScoredPair(
                trace_id=trace.trace_id,
                candidate_id=cand.trace_id,
                estimate=estimate,
                probability=proba,
                degraded=degraded,
            )
        )
    return out


def build_jobs(
    trace: Trace,
    candidates: list[Trace],
    features_of: dict[str, list[float]],
    estimates: dict[str, float],
) -> list[tuple[Trace, Trace, list[float], float]]:
    """Order candidate jobs best-first: highest estimated similarity first."""
    by_id = {c.trace_id: c for c in candidates}
    order = sorted(features_of, key=lambda tid: estimates.get(tid, 0.0), reverse=True)
    return [(trace, by_id[tid], features_of[tid], estimates.get(tid, 0.0)) for tid in order]
