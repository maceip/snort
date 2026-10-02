"""Focused checks for the v1 task slice: fusion + ledger + demo + ablations."""

import os

from snort.attrib.fusion import ActorAttributor
from snort.demo_data import make_cta_like, make_e3_like
from snort.eval.report import CONDITIONS, run_ablations
from snort.ledger import Ledger


def _trained():
    train, test, known, heldout = make_cta_like(seed=0)
    attr = ActorAttributor()
    attr.fit(
        [t.text() for t in train],
        [t.actor or "?" for t in train],
        [t.techniques for t in train],
    )
    by_actor = {}
    for t in test:
        by_actor.setdefault(t.actor, []).append(t)
    return attr, by_actor, known, heldout


def test_known_actor_gets_candidates_with_right_top():
    attr, by_actor, known, _ = _trained()
    t = by_actor[known[0]][0]
    res = attr.attribute_group("g", [t.text()], t.techniques)
    assert res.decision == "candidates", res
    assert res.ranking[0][0] == t.actor, res.ranking[:3]


def test_heldout_actor_is_unresolved():
    attr, by_actor, _, heldout = _trained()
    for h in heldout:
        t = by_actor[h][0]
        res = attr.attribute_group("g", [t.text()], t.techniques)
        assert res.decision == "unresolved", (h, res.ranking[:3])


def test_labelless_e3_group_is_unresolved():
    attr, _, _, _ = _trained()
    e3 = make_e3_like(seed=0)
    res = attr.attribute_group("e3-g0", [], e3[0].techniques)
    assert res.decision == "unresolved"
    assert res.unknown_posterior == 1.0


def test_command_only_never_attributed():
    attr, by_actor, known, _ = _trained()
    for t in by_actor[known[1]][:5]:
        res = attr.attribute_group("g", [t.text()], t.techniques)
        assert res.decision != "attributed", res


def test_ledger_verify_passes_and_detects_tamper(tmp_path):
    ledger = Ledger()
    ledger.append_segment(b"raw-bytes-1", {"source": "a"})
    ledger.append_segment(b"raw-bytes-2", {"source": "b"})
    ledger.append("links", [1], {"m": 1}, {"p": 1}, {"c": 1}, [2])
    ok, errors = ledger.verify()
    assert ok, errors
    p = os.path.join(str(tmp_path), "ledger.jsonl")
    ledger.save(p)
    assert Ledger.load(p).verify()[0]
    tampered = Ledger.load(p)
    tampered.records[1].context = {"source": "evil"}
    ok2, errors2 = tampered.verify()
    assert not ok2 and errors2
    truncated = Ledger.load(p)
    truncated.records.pop()
    ok3, _ = truncated.verify()
    assert ok3  # truncation of the tail is visible to the holder, not the hash
    assert len(truncated) == len(ledger) - 1


def test_ablation_report_has_three_stated_ablations():
    names = [n for n, _, _ in CONDITIONS]
    assert names[0] == "full pipeline"
    assert any("indicators only" in n for n in names)
    assert any("FIFO" in n for n in names)
    assert any("cosine" in n for n in names)
    rows, md = run_ablations(seeds=2)
    assert len(rows) == 4
    assert "no LSH" in md and "FIFO" in md and "cosine" in md
    full = next(r for r in rows if r["condition"] == "full pipeline")
    assert full["heldout_unresolved"] >= 0.5
    assert full["e3_unresolved"] == 1.0


def test_demo_smoke(tmp_path):
    from snort.cli import run_demo
    from snort.ledger import Ledger as L2

    out = os.path.join(str(tmp_path), "demo")
    summary = run_demo(out, seeds=2, budget=200)
    assert summary["verify_ok"], summary.get("verify_errors")
    assert os.path.exists(os.path.join(out, "ledger.jsonl"))
    assert os.path.exists(os.path.join(out, "metrics.md"))
    assert os.path.exists(os.path.join(out, "summary.json"))
    ok, _ = L2.load(os.path.join(out, "ledger.jsonl")).verify()
    assert ok
    assert {d["decision"] for d in summary["decisions"]} <= {"candidates", "unresolved"}
