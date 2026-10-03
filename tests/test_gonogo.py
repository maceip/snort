"""Focused tests for the two go/no-go checks, incl. GO and NO-GO paths."""

import json
import os
import sys

import pandas as pd

from lab.convert import event_schema as es
from lab.eval import gono_go1_boundaries as go1
from lab.eval import gono_go2_separability as go2


def _frames(traces_rows, events_rows, incidents):
    traces = pd.DataFrame(traces_rows)
    events = pd.DataFrame(events_rows)
    manifest = {"incidents": incidents}
    return events, traces, manifest


def _ev(h, subj, obj="o", ts=1000):
    return {"event_hash": h, "subject": subj, "object": obj, "ts": ts}


def _tr(tid, hashes):
    return {"trace_id": tid, "anchor": tid, "host": "h",
            "t_start": 1, "t_end": 2, "member_count": len(hashes),
            "text": "x", "event_hashes": json.dumps(hashes)}


def test_go1_passes_when_attack_is_compact_and_pure():
    events, traces, manifest = _frames(
        [_tr("t-attack", ["h1", "h2", "h3"]), _tr("t-benign", ["h4", "h5"])],
        [_ev("h1", "a1", "a2"), _ev("h2", "a2", "a1"), _ev("h3", "a1", "a1"),
         _ev("h4", "b1", "b2"), _ev("h5", "b2", "b3")],
        [{"incident_id": "atk", "attack_nodes": ["a1", "a2"]}],
    )
    rep = go1.evaluate_boundaries(events, traces, manifest)
    assert rep["verdict"] == "GO", rep
    assert rep["incidents"][0]["coverage_top3"] == 1.0
    assert rep["incidents"][0]["purity_top3"] == 1.0


def test_go1_fails_when_attack_scatters():
    traces_rows, events_rows = [], []
    for i in range(10):
        traces_rows.append(_tr(f"t{i}", [f"h{i}"]))
        events_rows.append(_ev(f"h{i}", f"a{i}", f"benign{i}"))
    events, traces, manifest = _frames(
        traces_rows, events_rows,
        [{"incident_id": "atk", "attack_nodes": [f"a{i}" for i in range(10)]}],
    )
    rep = go1.evaluate_boundaries(events, traces, manifest)
    assert rep["verdict"] == "NO-GO", rep
    assert rep["incidents"][0]["coverage_top3"] < 0.8


def test_go1_fails_when_trace_is_impure():
    events, traces, manifest = _frames(
        [_tr("t-big", ["h1"] + [f"b{i}" for i in range(9)])],
        [_ev("h1", "a1", "a2")] + [_ev(f"b{i}", f"x{i}", f"y{i}") for i in range(9)],
        [{"incident_id": "atk", "attack_nodes": ["a1", "a2"]}],
    )
    rep = go1.evaluate_boundaries(events, traces, manifest)
    assert rep["verdict"] == "NO-GO", rep
    assert rep["incidents"][0]["purity_top3"] == 0.1


def _trace_df(texts):
    return pd.DataFrame(
        [{"trace_id": f"t{i}", "anchor": f"t{i}", "host": "h", "t_start": 1,
          "t_end": 2, "member_count": 1, "text": t, "event_hashes": "[]"}
         for i, t in enumerate(texts)]
    )


def test_go2_passes_on_separable_traces():
    texts = (["mimikatz sekurlsa logonpasswords dcsync"] * 6
             + ["rubeus asktgt kerberoast opm"] * 6)
    groups = {f"t{i}": "A" for i in range(6)}
    groups.update({f"t{i}": "B" for i in range(6, 12)})
    rep = go2.evaluate_separability(_trace_df(texts), groups, n_pairs=30, seed=7)
    assert rep["verdict"] == "GO", rep
    assert max(rep["auc_minhash_jaccard"], rep["auc_tfidf_cosine"]) >= 0.8


def test_go2_fails_on_inseparable_traces():
    texts = ["mimikatz sekurlsa rubeus asktgt common lubrication"] * 12
    groups = {f"t{i}": ("A" if i % 2 else "B") for i in range(12)}
    rep = go2.evaluate_separability(_trace_df(texts), groups, n_pairs=30, seed=7)
    assert rep["verdict"] == "NO-GO", rep


def test_go2_unresolved_with_single_group():
    rep = go2.evaluate_separability(_trace_df(["alpha beta"] * 3),
                                    {"t0": "A", "t1": "A", "t2": "A"})
    assert rep["verdict"] == "UNRESOLVED"


def test_go1_cli_writes_report(tmp_path):
    d = str(tmp_path)
    events = pd.DataFrame([_ev("h1", "a1", "a2"), _ev("h2", "b1", "b2")])
    traces = pd.DataFrame([_tr("t1", ["h1"]), _tr("t2", ["h2"])])
    es.to_parquet(events.assign(host="h", source_id="s", source_seq=[0, 1],
                                ingest_ts=1, action="A", template_hash="t", raw="{}"),
                  os.path.join(d, "events.parquet"))
    es.to_parquet(traces, os.path.join(d, "traces.parquet"))
    es.dump_json({"incidents": [{"incident_id": "atk", "attack_nodes": ["a1"]}]},
                 os.path.join(d, "manifest.json"))
    import subprocess

    out = os.path.join(d, "report.json")
    # Use sys.executable so the subprocess runs the same interpreter (and therefore
    # the same environment) as the test run; a bare "python3" may resolve elsewhere.
    p = subprocess.run([sys.executable, "-m", "lab.eval.gono_go1_boundaries",
                        "--events", os.path.join(d, "events.parquet"),
                        "--traces", os.path.join(d, "traces.parquet"),
                        "--manifest", os.path.join(d, "manifest.json"),
                        "--out", out],
                       capture_output=True, text=True, cwd=os.getcwd())
    assert p.returncode == 0, p.stderr
    assert es.load_json(out)["verdict"] in ("GO", "NO-GO")
