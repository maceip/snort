"""Subsystem 4: Progressive Matching, PER Anti-Hub Priority Queue & Calibrated Pair Model."""

import numpy as np
from snort.match.features import (
    FEATURE_NAMES,
    PairFeatureContext,
    estimate_similarity,
    pair_cost,
    pair_features,
)
from snort.match.pair_model import CalibratedPairModel
from snort.match.queue import BestFirstQueue
from snort.trace.signatures import Trace, build_idf


def make_trace_pair(
    t1_tokens: list[str],
    t2_tokens: list[str],
    t1_ind: set[str] | None = None,
    t2_ind: set[str] | None = None,
) -> tuple[Trace, Trace]:
    t1 = Trace(
        trace_id="trace_1",
        tokens=tuple(t1_tokens),
        indicators=frozenset(t1_ind or []),
        start_ts=100.0,
        end_ts=110.0,
    )
    t2 = Trace(
        trace_id="trace_2",
        tokens=tuple(t2_tokens),
        indicators=frozenset(t2_ind or []),
        start_ts=105.0,
        end_ts=120.0,
    )
    return t1, t2


def test_match_subsystem_queue_and_model():
    """Verify PER anti-hub queue weighting, pairwise feature extraction, and calibrated logistic scoring."""
    # 1. PER Reciprocal Degree Anti-Hub Queue Weighting
    queue = BestFirstQueue(budget_per_round=100.0)

    # Anomaly pair: high similarity (0.8), low degrees (deg_u=2, deg_v=2)
    # Priority = 0.8 / sqrt(2 * 2) = 0.4
    queue.push(
        trace_id="stealth_u",
        candidate_id="stealth_v",
        estimate=0.8,
        cost=1.0,
        deg_u=2,
        deg_v=2,
    )

    # Hub daemon pair: high similarity (0.9), but huge degrees (deg_u=100, deg_v=100)
    # Priority = 0.9 / sqrt(100 * 100) = 0.009
    queue.push(
        trace_id="hub_daemon_u",
        candidate_id="hub_daemon_v",
        estimate=0.9,
        cost=1.0,
        deg_u=100,
        deg_v=100,
    )

    # Anomaly pair MUST be popped before noisy hub daemon, despite lower raw estimate
    popped = queue.pop_round()
    assert len(popped) == 2
    assert popped[0][0] == "stealth_u"
    assert popped[1][0] == "hub_daemon_u"

    # 2. Pairwise Feature Extraction
    t1, t2 = make_trace_pair(
        t1_tokens=["cmd_a", "cmd_b", "cmd_c"],
        t2_tokens=["cmd_a", "cmd_b", "cmd_d"],
        t1_ind={"ip:192.168.1.1"},
        t2_ind={"ip:192.168.1.1"},
    )
    idf = build_idf([t1.tokens, t2.tokens])
    ctx = PairFeatureContext(token_idf=idf)

    feats = pair_features(t1, t2, ctx)
    assert len(feats) == len(FEATURE_NAMES)
    est = estimate_similarity(t1, t2, ctx)
    assert 0.0 <= est <= 1.0
    cost = pair_cost(t1, t2)
    assert cost > 0.0

    # 3. Calibrated Logistic Pair Model
    # Synthesize small training set with distinct positive and negative feature distributions
    rng = np.random.RandomState(42)
    num_features = len(FEATURE_NAMES)
    X_pos = rng.normal(loc=0.8, scale=0.1, size=(20, num_features)).clip(0, 1)
    X_neg = rng.normal(loc=0.1, scale=0.1, size=(20, num_features)).clip(0, 1)
    X = np.vstack([X_pos, X_neg]).tolist()
    y = [1] * 20 + [0] * 20

    model = CalibratedPairModel(seed=42)
    model.fit(X, y)
    assert model.fitted is True

    # High similarity test pair -> calibrated prob > 0.7
    prob_high = model.predict_proba([X_pos[0].tolist()])[0]
    prob_low = model.predict_proba([X_neg[0].tolist()])[0]
    assert prob_high > 0.7
    assert prob_low < 0.3

    # Explanation contributions
    contribs = model.contributions(X_pos[0].tolist())
    assert len(contribs) == num_features


def test_reciprocal_degree_weighting_can_be_disabled():
    queue = BestFirstQueue(reciprocal_degree=False)
    queue.push("rare", "rare-peer", 0.8, deg_u=2, deg_v=2)
    queue.push("hub", "hub-peer", 0.9, deg_u=100, deg_v=100)
    assert [tid for tid, _, _ in queue.pop_round()] == ["hub", "rare"]
