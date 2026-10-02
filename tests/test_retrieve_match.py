"""Focused tests for version-1 retrieval and calibrated scoring."""

from __future__ import annotations

import math
import random

import numpy as np
import pytest

from snort.match.features import (
    FEATURE_NAMES,
    PairFeatureContext,
    estimate_similarity,
    pair_cost,
    pair_features,
)
from snort.match.pair_model import CalibratedPairModel
from snort.match.queue import BestFirstQueue, build_jobs, score_with_budget
from snort.retrieve.candidates import CandidateRetriever
from snort.retrieve.indicators import IndicatorIndex
from snort.retrieve.minhash_lsh import MinHashLSHIndex, bands_for_threshold
from snort.retrieve.provenance import ProvenanceGraph
from snort.trace.signatures import (
    Trace,
    build_idf,
    exact_jaccard,
    minhash_jaccard,
    shingle_tokens,
    tfidf_cosine,
)

VOCAB = [f"cmd{i}" for i in range(40)]


def make_trace(
    tid: str,
    tokens: list[str],
    start: float = 0.0,
    indicators: frozenset[str] = frozenset(),
    techniques: frozenset[str] = frozenset(),
    entities: frozenset[str] = frozenset(),
) -> Trace:
    return Trace(
        trace_id=tid,
        tokens=tuple(tokens),
        techniques=techniques,
        indicators=indicators,
        entities=entities,
        start_ts=start,
        end_ts=start + max(1.0, len(tokens)),
    )


def test_minhash_estimate_tracks_exact_jaccard() -> None:
    rng = random.Random(0)
    for _ in range(5):
        a = frozenset(rng.sample(VOCAB, 12))
        b = frozenset(rng.sample(VOCAB, 12))
        sa = tuple(sorted(a))
        ta = make_trace("a", [str(x) for x in sa])
        tb = make_trace("b", [str(x) for x in sorted(b)])
        exact = exact_jaccard(ta.shingles, tb.shingles)
        est = minhash_jaccard(ta.signature, tb.signature)
        assert abs(est - exact) < 0.15


def test_bands_come_from_theta() -> None:
    b_lo, r_lo = bands_for_threshold(128, 0.3)
    b_hi, r_hi = bands_for_threshold(128, 0.8)
    assert b_lo * r_lo == 128 and b_hi * r_hi == 128
    t_lo = (1.0 / b_lo) ** (1.0 / r_lo)
    t_hi = (1.0 / b_hi) ** (1.0 / r_hi)
    assert abs(t_lo - 0.3) < 0.2 and abs(t_hi - 0.8) < 0.2
    assert (b_lo, r_lo) != (b_hi, r_hi)


def test_lsh_recalls_near_duplicates() -> None:
    index = MinHashLSHIndex(theta=0.5)
    base = [f"cmd{i}" for i in range(20)]
    index.insert("base", make_trace("base", base).signature)
    near = base[:18] + ["cmdX", "cmdY"]
    index.insert("near", make_trace("near", near).signature)
    far = [f"other{i}" for i in range(20)]
    index.insert("far", make_trace("far", far).signature)
    hits = dict(index.query(make_trace("q", base).signature))
    assert "near" in hits
    assert hits.get("near", 0.0) > hits.get("far", 0.0)


def test_lsh_reinsert_and_bounded_store() -> None:
    index = MinHashLSHIndex(max_vectors=3)
    for i in range(4):
        index.insert(f"t{i}", make_trace(f"t{i}", [f"tok{i}", "shared"]).signature)
    assert len(index) == 3
    # Reinserting an evicted id works and keeps the id separate from content.
    index.insert("t0", make_trace("t0", ["brand", "new"]).signature)
    assert len(index) == 3


def test_indicator_exact_lookup_and_common_skip() -> None:
    index = IndicatorIndex()
    for i in range(150):
        index.add(f"t{i}", frozenset({"common-key", f"rare-{i}"}))
    assert index.is_too_common("common-key")
    assert not index.is_too_common("rare-0")
    hits = index.query(frozenset({"common-key"}))
    assert hits == {}
    hits = index.query(frozenset({"rare-3"}))
    assert hits == {"t3": 1}


def test_indicator_posting_cap() -> None:
    index = IndicatorIndex(posting_cap=5)
    for i in range(8):
        index.add(f"t{i}", frozenset({"k"}))
    assert len(index._postings["k"]) == 5
    assert "t0" not in index._postings["k"]


def test_provenance_path_within_15_minutes() -> None:
    g = ProvenanceGraph()
    g.add_trace("a", frozenset({"proc:1"}), 0.0)
    g.add_trace("b", frozenset({"proc:1"}), 600.0)
    g.add_trace("c", frozenset({"proc:1"}), 3600.0)
    g.add_trace("d", frozenset({"proc:9"}), 100.0)
    assert g.has_path("a", "b")
    assert not g.has_path("a", "c")
    assert not g.has_path("a", "d")
    assert set(g.related("a")) == {"b"}


def test_candidate_union_capped_at_50() -> None:
    lsh = MinHashLSHIndex(theta=0.3)
    ind = IndicatorIndex()
    prov = ProvenanceGraph()
    ret = CandidateRetriever(lsh, ind, prov)
    query = make_trace("q", [f"cmd{i}" for i in range(10)], entities=frozenset({"h"}))
    for i in range(60):
        t = make_trace(
            f"t{i}",
            [f"cmd{(i + j) % 12}" for j in range(10)],
            indicators=frozenset({f"ind{i}"}),
            entities=frozenset({"h"}),
            start=i,
        )
        ret.index_trace(t)
    ret.index_trace(query)
    cands = ret.retrieve(query)
    assert len(cands) <= 50
    assert all("provenance" in c.sources for c in cands)


def test_pair_features_cover_plan_slots() -> None:
    assert len(FEATURE_NAMES) == 8
    for name in (
        "minhash_jaccard",
        "tfidf_cosine",
        "idf_shared_indicators",
        "technique_jaccard",
        "provenance_path",
        "time_gap_log",
    ):
        assert name in FEATURE_NAMES
    ind = IndicatorIndex()
    prov = ProvenanceGraph()
    a = make_trace(
        "a",
        ["x", "y", "z"],
        indicators=frozenset({"i1"}),
        techniques=frozenset({"T1"}),
        entities=frozenset({"e"}),
    )
    b = make_trace(
        "b",
        ["x", "y", "w"],
        start=120.0,
        indicators=frozenset({"i1"}),
        techniques=frozenset({"T1", "T2"}),
        entities=frozenset({"e"}),
    )
    for t in (a, b):
        ind.add(t.trace_id, t.indicators)
        prov.add_trace(t.trace_id, t.entities, t.start_ts)
    ctx = PairFeatureContext(
        token_idf=build_idf([a.token_counts, b.token_counts]),
        indicators=ind,
        provenance=prov,
    )
    feats = pair_features(a, b, ctx)
    assert len(feats) == 8
    by_name = dict(zip(FEATURE_NAMES, feats))
    assert by_name["provenance_path"] == 1.0
    assert by_name["technique_jaccard"] == pytest.approx(0.5)
    assert by_name["shared_indicator_count"] == 1.0
    assert by_name["time_gap_log"] == pytest.approx(math.log1p(2.0))
    assert 0.0 <= by_name["tfidf_cosine"] <= 1.0
    assert estimate_similarity(a, b, ctx) > estimate_similarity(
        a, make_trace("z", ["unrelated", "tokens", "here"]), ctx
    )


def test_pair_cost_counts_sequence_cells() -> None:
    a = make_trace("a", ["t"] * 10)
    b = make_trace("b", ["t"] * 20)
    assert pair_cost(a, b, model_cost=1.0) == 10 * 20 + 1.0


def _synthetic_pairs(seed: int = 0) -> tuple[list[list[float]], list[int]]:
    rng = random.Random(seed)
    X: list[list[float]] = []
    y: list[int] = []
    for _ in range(60):
        sim = rng.random() < 0.5
        if sim:
            row = [
                rng.uniform(0.6, 1.0),
                rng.uniform(0.5, 1.0),
                rng.uniform(1.0, 5.0),
                rng.uniform(0.4, 1.0),
                1.0 if rng.random() < 0.7 else 0.0,
                rng.uniform(0.0, 1.0),
                float(rng.randint(1, 4)),
                rng.uniform(0.6, 1.0),
            ]
            y.append(1)
        else:
            row = [
                rng.uniform(0.0, 0.3),
                rng.uniform(0.0, 0.3),
                0.0,
                0.0,
                0.0,
                rng.uniform(2.0, 6.0),
                0.0,
                rng.uniform(0.0, 0.5),
            ]
            y.append(0)
        X.append(row)
    return X, y


def test_calibrated_model_separates_and_calibrates() -> None:
    X, y = _synthetic_pairs()
    model = CalibratedPairModel().fit(X, y)
    probs = model.predict_proba(X)
    assert np.all(probs >= 0.0) and np.all(probs <= 1.0)
    pos = probs[np.asarray(y) == 1].mean()
    neg = probs[np.asarray(y) == 0].mean()
    assert pos > 0.7 > neg
    assert model.calibration_error(X, y) < 0.25
    # Contributions explain the raw margin.
    x = X[0]
    contrib = model.contributions(x)
    assert set(contrib) == set(FEATURE_NAMES)
    assert sum(contrib.values()) + float(model.clf.intercept_[0]) == pytest.approx(
        float(model.raw_margin([x])[0])
    )
    assert "model_hash" in model.decision_context()


def test_queue_is_best_first_and_budgeted() -> None:
    q = BestFirstQueue(budget_per_round=10.0)
    q.push("t", "c1", estimate=0.9, cost=6.0)
    q.push("t", "c2", estimate=0.5, cost=6.0)
    q.push("t", "c3", estimate=0.99, cost=4.0)
    first = q.pop_round()
    assert [c for _, c, _ in first] == ["c3", "c1"]
    assert len(q) == 1
    second = q.pop_round()
    assert [c for _, c, _ in second] == ["c2"]


def test_score_with_budget_flags_degraded() -> None:
    X, y = _synthetic_pairs()
    model = CalibratedPairModel().fit(X, y)
    a = make_trace("a", ["x", "y"])
    b = make_trace("b", ["x", "z"])
    jobs = [(a, b, X[0], 0.8)]
    ok = score_with_budget(jobs, model, wall_cap_s=3600.0)
    assert len(ok) == 1 and not ok[0].degraded
    assert 0.0 <= ok[0].probability <= 1.0
    forced = score_with_budget(jobs, model, wall_cap_s=0.0)
    assert forced[0].degraded


def test_build_jobs_orders_by_estimate() -> None:
    t = make_trace("t", ["a"])
    cands = [make_trace("c1", ["a"]), make_trace("c2", ["b"])]
    jobs = build_jobs(
        t, cands, {"c1": [0.1] * 8, "c2": [0.9] * 8}, {"c1": 0.1, "c2": 0.9}
    )
    assert [c.trace_id for _, c, _, _ in jobs] == ["c2", "c1"]


def test_tfidf_and_shingles_basics() -> None:
    toks = ["a", "b", "a"]
    assert "1g:a" in shingle_tokens(toks) and "2g:a\x1fb" in shingle_tokens(toks)
    idf = build_idf([{t: toks.count(t) for t in set(toks)}])
    assert tfidf_cosine({t: toks.count(t) for t in set(toks)}, {}, idf) == 0.0
