"""Subsystem 6: Behavioral Threat Attribution, Open-Set Unresolved & CTAs Fusion."""

from snort.attrib.fusion import ActorAttributor
from snort.demo_data import make_cta_like, make_e3_like


def test_attrib_subsystem_classification_and_unresolved():
    """Verify known actor candidate ranking, held-out unresolved decision, and unknown posterior."""
    train_traces, test_traces, known_actors, heldout_actors = make_cta_like(seed=42)

    attributor = ActorAttributor()
    attributor.fit(
        texts=[t.text() for t in train_traces],
        actors=[t.actor or "unknown" for t in train_traces],
        techniques=[t.techniques for t in train_traces],
    )

    # 1. Known threat actor group: returns 'candidates' decision with correct top rank
    by_actor = {}
    for t in test_traces:
        by_actor.setdefault(t.actor, []).append(t)

    target_actor = known_actors[0]
    known_test_trace = by_actor[target_actor][0]
    result_known = attributor.attribute_group(
        group_id="grp_known",
        texts=[known_test_trace.text()],
        techniques=known_test_trace.techniques,
    )
    assert result_known.decision == "candidates"
    assert len(result_known.ranking) > 0
    assert result_known.ranking[0][0] == target_actor

    # 2. Held-out / novel threat actor (Open-Set): MUST return 'unresolved'
    for heldout in heldout_actors:
        heldout_trace = by_actor[heldout][0]
        result_heldout = attributor.attribute_group(
            group_id="grp_heldout",
            texts=[heldout_trace.text()],
            techniques=heldout_trace.techniques,
        )
        assert result_heldout.decision == "unresolved"

    # 3. Labelless benign / system group (E3 like): MUST return 'unresolved' with 1.0 unknown posterior
    e3_traces = make_e3_like(seed=42)
    result_e3 = attributor.attribute_group(
        group_id="grp_e3",
        texts=[],
        techniques=e3_traces[0].techniques,
    )
    assert result_e3.decision == "unresolved"
    assert result_e3.unknown_posterior == 1.0

    # 4. Command-only sessions without independent multi-class evidence never jump to high-confidence 'attributed'
    for t in by_actor[known_actors[1]][:3]:
        res = attributor.attribute_group("grp_cmd_only", [t.text()], t.techniques)
        assert res.decision != "attributed"
