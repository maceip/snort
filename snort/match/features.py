"""Pair features for the version-1 logistic pair model (plan section 4.4).

Eight features in six evidence classes: behaviour sequence (MinHash
Jaccard), execution content (TF-IDF cosine, technique overlap), tooling /
infrastructure (IDF-weighted shared indicators + raw shared count),
causality (provenance path within 15 minutes), timing (gap, duration).
"""

from __future__ import annotations

import math
from collections import Counter

from snort.retrieve.indicators import IndicatorIndex
from snort.retrieve.provenance import ProvenanceGraph
from snort.trace.signatures import (
    exact_jaccard,
    minhash_jaccard,
    tfidf_cosine,
    Trace,
)

FEATURE_NAMES: tuple[str, ...] = (
    "minhash_jaccard",
    "tfidf_cosine",
    "idf_shared_indicators",
    "technique_jaccard",
    "provenance_path",
    "time_gap_log",
    "shared_indicator_count",
    "duration_sim",
)


def duration_sim(a: Trace, b: Trace) -> float:
    da, db = a.duration, b.duration
    if da == 0.0 and db == 0.0:
        return 1.0
    if da == 0.0 or db == 0.0:
        return 0.0
    return 1.0 / (1.0 + abs(math.log(da / db)))


class PairFeatureContext:
    """Shared state needed to featurize pairs (IDF, provenance)."""

    def __init__(
        self,
        token_idf: dict[str, float] | None = None,
        indicators: IndicatorIndex | None = None,
        provenance: ProvenanceGraph | None = None,
    ) -> None:
        self.token_idf = token_idf or {}
        self.indicators = indicators or IndicatorIndex()
        self.provenance = provenance or ProvenanceGraph()


def pair_features(a: Trace, b: Trace, ctx: PairFeatureContext) -> list[float]:
    shared_indicators = a.indicators & b.indicators
    gap_s = abs(a.start_ts - b.start_ts)
    return [
        minhash_jaccard(a.signature, b.signature),
        tfidf_cosine(a.token_counts, b.token_counts, ctx.token_idf),
        ctx.indicators.idf_shared_weight(a.indicators, b.indicators),
        exact_jaccard(a.techniques, b.techniques),
        1.0 if ctx.provenance.has_path(a.trace_id, b.trace_id) else 0.0,
        math.log1p(gap_s / 60.0),
        float(len(shared_indicators)),
        duration_sim(a, b),
    ]


def featurize_pairs(
    pairs: list[tuple[Trace, Trace]], ctx: PairFeatureContext
) -> list[list[float]]:
    return [pair_features(a, b, ctx) for a, b in pairs]


def estimate_similarity(a: Trace, b: Trace, ctx: PairFeatureContext) -> float:
    """Cheap pre-score used to order the best-first queue.

    Weighted blend of the normalized similarity features in [0, 1].
    """
    feats = pair_features(a, b, ctx)
    idf_norm = feats[2] / (1.0 + feats[2])
    return float(0.45 * feats[0] + 0.30 * feats[1] + 0.15 * feats[3] + 0.10 * idf_norm)


def pair_cost(a: Trace, b: Trace, model_cost: float = 1.0) -> float:
    """Comparison cost: sequence cells plus a fixed model cost (plan 4.4)."""
    cells = min(len(a.tokens), 256) * min(len(b.tokens), 256)
    return float(cells + model_cost)
