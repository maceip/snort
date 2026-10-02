"""Focused checks for overlapping memberships (plan section 4.5)."""

from snort.group import GroupManager, ScoredLink, membership_strength


def link(other, prob, classes=("technique", "infrastructure"), **kw):
    return ScoredLink(
        other_trace_id=other, probability=prob, evidence_classes=tuple(classes),
        contributions=kw.get("contributions", {"technique": prob}),
        shared_shingles=kw.get("shared_shingles", ("sh1",)),
        shared_indicators=kw.get("shared_indicators", ("10.0.0.1",)),
        event_hashes=kw.get("event_hashes", ("h1",)),
    )


def test_strength_mean_top3_and_blend():
    assert membership_strength([]) == 0.0
    assert abs(membership_strength([0.9, 0.7, 0.5, 0.1]) - 0.7) < 1e-9
    assert abs(membership_strength([0.9, 0.7, 0.5, 0.1], 0.7) - 0.7) < 1e-9
    assert abs(membership_strength([1.0], 0.0) - 0.7) < 1e-9


def test_seed_requires_two_evidence_classes_and_threshold():
    mgr = GroupManager()
    assert mgr.maybe_seed("a", "b", 0.9, ("technique",)) is None
    assert mgr.maybe_seed("a", "b", 0.5, ("technique", "infra")) is None
    gid = mgr.maybe_seed("a", "b", 0.9, ("technique", "infra"))
    assert gid is not None and set(mgr.groups[gid].members) == {"a", "b"}


def test_overlap_without_transitive_closure():
    mgr = GroupManager()
    g1 = mgr.maybe_seed("a", "b", 0.9, ("c1", "c2"))
    # b-c strong but b already shares g1 with a; c shares no group with b? b IS in g1,
    # c is new -> allowed, creates overlapping second group for b.
    g2 = mgr.maybe_seed("b", "c", 0.9, ("c1", "c2"))
    assert g1 != g2 and "b" in mgr.groups[g1].members and "b" in mgr.groups[g2].members
    # a and c share no group: no auto-merge happened.
    assert mgr.shared_groups("a", "c") == []
    # a-b pair sharing g1 must not seed again.
    assert mgr.maybe_seed("a", "b", 0.95, ("c1", "c2")) is None


def test_cap_three_and_unassigned():
    mgr = GroupManager()
    for other in ("m1", "m2", "m3", "m4"):
        mgr.groups[other] = mgr.groups.get(other) or __import__("snort.group", fromlist=["Group"]).Group(group_id=other)
        mgr.groups[other].members[other] = __import__("snort.group", fromlist=["Membership"]).Membership(other, other, 1.0, evidence={})
    links = {gid: [link(gid, 0.9)] for gid in ("m1", "m2", "m3", "m4")}
    scored = mgr.score_trace("t", links)
    assert len(scored) == 3
    weak = mgr.score_trace("t", {"m1": [link("m1", 0.1)]})
    assert weak == []


def test_per_membership_evidence_contents():
    mgr = GroupManager()
    mgr.groups["g"] = __import__("snort.group", fromlist=["Group"]).Group(group_id="g")
    mgr.groups["g"].members["m"] = __import__("snort.group", fromlist=["Membership"]).Membership("m", "g", 1.0, evidence={})
    made = mgr.assign("t", {"g": [link("m", 0.9, contributions={"a": 0.5, "b": 0.2},
                                       shared_shingles=("s1",), shared_indicators=("i1",),
                                       event_hashes=("e1",))]})
    assert len(made) == 1
    ev = made[0].evidence
    assert ev["top_contributions"][0][0] == "a"
    assert ev["shared_shingles"] == ["s1"] and ev["event_hashes"] == ["e1"]


def test_analyst_labels_are_trace_group_only():
    mgr = GroupManager()
    gid = mgr.maybe_seed("a", "b", 0.9, ("c1", "c2"))
    mgr.analyst_decide("a", gid, "analyst-confirmed")
    assert mgr.groups[gid].members["a"].state == "analyst-confirmed"
    assert mgr.analyst_labels[("a", gid)] == "analyst-confirmed"
    try:
        mgr.analyst_decide("a", gid, "bogus")
    except ValueError:
        pass
    else:
        raise AssertionError("bad decision accepted")


def test_merge_proposals_only_on_shared_strong_members():
    mgr = GroupManager()
    g1 = mgr.maybe_seed("a", "b", 0.9, ("c1", "c2"))
    g2 = mgr.maybe_seed("b", "c", 0.9, ("c1", "c2"))
    props = mgr.merge_proposals()
    assert (g1, g2, ["b"]) in props or (g2, g1, ["b"]) in props
    # Groups must still be distinct: proposals never auto-merge.
    assert g1 in mgr.groups and g2 in mgr.groups


if __name__ == "__main__":
    for name, fn in sorted({k: v for k, v in globals().items() if k.startswith("test_")}.items()):
        fn()
        print(f"PASS {name}")
