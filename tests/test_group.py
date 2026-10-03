"""Subsystem 5: Incident Grouping, Overlapping Memberships & Guardrails."""

import pytest
from snort.group import Group, GroupManager, Membership, ScoredLink


def make_link(
    other_id: str,
    prob: float,
    classes: tuple[str, ...] = ("technique", "infrastructure"),
    **kw,
) -> ScoredLink:
    return ScoredLink(
        other_trace_id=other_id,
        probability=prob,
        evidence_classes=classes,
        contributions=kw.get("contributions", {"technique": prob}),
        shared_shingles=kw.get("shared_shingles", ("shingle_1",)),
        shared_indicators=kw.get("shared_indicators", ("192.168.1.1",)),
        event_hashes=kw.get("event_hashes", ("hash_1",)),
    )


def test_group_subsystem_overlapping_and_isolation():
    """Verify multi-evidence seeding, no transitive closure, max 3 memberships, and analyst review."""
    mgr = GroupManager()

    # 1. Multi-class evidence requirement for seeding
    # Seeding rejected with single evidence class even if prob is high
    assert mgr.maybe_seed("t1", "t2", 0.95, ("technique",)) is None
    # Seeding rejected if prob < threshold
    assert mgr.maybe_seed("t1", "t2", 0.60, ("technique", "infrastructure")) is None
    # Seeding succeeds with 2 classes and prob >= 0.80
    g1 = mgr.maybe_seed("t1", "t2", 0.88, ("technique", "infrastructure"))
    assert g1 is not None
    assert set(mgr.groups[g1].members.keys()) == {"t1", "t2"}

    # 2. Overlapping Groups Without Transitive Closure
    # t2 links strongly with new trace t3 -> creates a distinct second group g2 containing t2 and t3
    g2 = mgr.maybe_seed("t2", "t3", 0.85, ("technique", "infrastructure"))
    assert g2 is not None
    assert g1 != g2
    assert "t2" in mgr.groups[g1].members
    assert "t2" in mgr.groups[g2].members

    # Guardrail Check: Transitive closure DID NOT happen!
    # t1 and t3 share NO groups; their environments remain cleanly isolated
    assert mgr.shared_groups("t1", "t3") == []

    # 3. Hard Cap of 3 Memberships Per Trace
    # Setup 4 groups
    for gid in ("g_alpha", "g_beta", "g_gamma", "g_delta"):
        mgr.groups[gid] = Group(group_id=gid)
        mgr.groups[gid].members[gid] = Membership(
            trace_id=gid, group_id=gid, strength=1.0, evidence={}
        )

    links = {
        gid: [make_link(gid, 0.90)]
        for gid in ("g_alpha", "g_beta", "g_gamma", "g_delta")
    }
    scored = mgr.score_trace("new_trace", links)
    # Even though 4 groups qualify, at most 3 are scored/assigned
    assert len(scored) == 3

    # Ambiguous / weak traces (< threshold) score 0 and remain unassigned singletons
    weak_links = {"g_alpha": [make_link("g_alpha", 0.15)]}
    assert mgr.score_trace("weak_trace", weak_links) == []

    # 4. Analyst Feedback & Immutable Decision States
    mgr.analyst_decide("t1", g1, "analyst-confirmed")
    assert mgr.groups[g1].members["t1"].state == "analyst-confirmed"
    assert mgr.analyst_labels[("t1", g1)] == "analyst-confirmed"

    with pytest.raises(ValueError):
        mgr.analyst_decide("t1", g1, "invalid_decision_state")

    # 5. Merge proposals on shared strong members without automated collapse
    props = mgr.merge_proposals()
    assert any(
        (p[0] == g1 and p[1] == g2 and "t2" in p[2])
        or (p[0] == g2 and p[1] == g1 and "t2" in p[2])
        for p in props
    )
    # Groups still remain separate until human intervention
    assert g1 in mgr.groups and g2 in mgr.groups
