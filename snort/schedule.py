"""Scheduling: best-first progressive queue vs FIFO ablation.

V1 subset of plan section 4.4: each trace's candidates are scored in order
of estimated similarity (MinHash Jaccard) under a per-run comparison
budget. The ablation serves candidates in insertion (FIFO) order.
"""

from __future__ import annotations

from snort.features import minhash_jaccard
from snort.retrieve import RetrievalIndex


def order_candidates(
    index: RetrievalIndex, tid: str, cands: list[str], mode: str
) -> list[str]:
    if mode == "best_first":
        t = index.traces[tid]
        return sorted(
            cands,
            key=lambda c: minhash_jaccard(t.minhash, index.traces[c].minhash),
            reverse=True,
        )
    if mode == "fifo":
        # Insertion order, ignoring the retrieval ranking: the ablation
        # must actually remove best-first prioritisation.
        return sorted(cands, key=lambda c: index.insert_pos.get(c, 0))
    raise ValueError(f"unknown schedule mode {mode!r}")


def budgeted_pairs(
    index: RetrievalIndex,
    tids: list[str],
    candidate_map: dict[str, list[str]],
    schedule: str,
    budget: int,
) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    per_trace = {tid: order_candidates(index, tid, candidate_map[tid], schedule) for tid in tids}
    # One candidate per trace per round (plan section 4.4).
    round_i = 0
    while len(pairs) < budget:
        progressed = False
        for tid in tids:
            q = per_trace[tid]
            if round_i < len(q) and len(pairs) < budget:
                pairs.append((tid, q[round_i]))
                progressed = True
        if not progressed:
            break
        round_i += 1
    return pairs
