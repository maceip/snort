"""Focused tests for the weeks 1-2 converters and splits."""

import json
import os

import pandas as pd

from lab.convert import cta, e3_cadets, event_schema as es
from lab.convert.splits import open_set_actor_split, time_forward_split


def _write(path, content):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def test_e3_converter_end_to_end(tmp_path):
    d = str(tmp_path)
    _write(os.path.join(d, "edges.csv"),
           "edge_id,ts,host,src_id,dst_id,action\n"
           "e1,1000,h1,10,11,FORK\n"
           "e2,2000,h1,11,12,EXECUTE\n"
           "e3,3000,h1,12,12,WRITE\n"
           "e4,4000,h1,20,21,READ\n")
    _write(os.path.join(d, "ancestry.csv"),
           "child,parent,image\n1,0,sshd\n2,0,systemd\n"
           "10,1,sh\n11,10,sh\n12,11,implant\n20,2,cron\n")
    os.mkdir(os.path.join(d, "gt"))
    _write(os.path.join(d, "gt", "attack1.csv"), "node_id\n11\n12\n")
    out = os.path.join(d, "out")
    stats = e3_cadets.convert_e3(os.path.join(d, "edges.csv"), out,
                                 ancestry_path=os.path.join(d, "ancestry.csv"),
                                 ground_truth_dir=os.path.join(d, "gt"))
    assert stats == {"events": 4, "traces": 2, "incidents": 1, "out_dir": out}
    for fn in ("events.parquet", "traces.parquet", "manifest.json", "splits.json"):
        assert os.path.exists(os.path.join(out, fn)), fn
    events = es.read_parquet(os.path.join(out, "events.parquet"))
    assert list(events["source_seq"]) == [0, 1, 2, 3]
    assert events["event_hash"].is_unique
    manifest = es.load_json(os.path.join(out, "manifest.json"))
    assert manifest["incidents"][0]["incident_id"] == "attack1"
    assert manifest["incidents"][0]["attack_nodes"] == ["11", "12"]
    traces = es.read_parquet(os.path.join(out, "traces.parquet"))
    assert set(traces["trace_id"]) == {"h1::10", "h1::20"}


def test_e3_converter_rejects_bad_edges(tmp_path):
    d = str(tmp_path)
    _write(os.path.join(d, "edges.csv"), "edge_id,ts\n1,2\n")
    try:
        e3_cadets.convert_e3(os.path.join(d, "edges.csv"), os.path.join(d, "o"))
    except ValueError as exc:
        assert "src_id" in str(exc) or "required column" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def _cta_record(actor, session, ts, text, tactic="execution"):
    return {"actor": actor, "session_id": session, "timestamp": ts,
            "command": text, "type": "EXEC", "tactic": tactic}


def test_cta_converter_end_to_end(tmp_path):
    d = str(tmp_path)
    recs = []
    for i in range(10):
        recs.append(_cta_record("apt1", f"s{i}", 1_000 + i, f"mimikatz sekurlsa {i}"))
        recs.append(_cta_record("apt2", f"t{i}", 2_000 + i, f"rubeus asktgt {i}"))
    recs.append(_cta_record("plki-foo", "sf0", 1500, "whoami test"))
    recs.append(_cta_record("other", "o0", 1500, "junk junk"))
    recs.append(_cta_record("apt1", "long1", 1500, " ".join(["word"] * 300)))
    with open(os.path.join(d, "cta.json"), "w") as fh:
        json.dump(recs, fh)
    out = os.path.join(d, "out")
    stats = cta.convert_cta(os.path.join(d, "cta.json"), out)
    assert stats["actors"] == 3  # apt1, apt2, sf
    manifest = es.load_json(os.path.join(out, "manifest.json"))
    assert "sf" in manifest["actors"] and "other" not in manifest["actors"]
    assert "plki-foo" not in manifest["actors"]
    assert manifest["preprocessing"]["dropped_other"] == 1
    assert manifest["preprocessing"]["dropped_long_session_commands"] == 1
    events = es.read_parquet(os.path.join(out, "events.parquet"))
    assert "raw_text" not in events.columns  # helper column stays out of the schema
    splits = es.load_json(os.path.join(out, "splits.json"))
    for actor, sp in splits["per_actor_time_forward"].items():
        train = set(sp["train"])
        assert not (train & set(sp["val"]) or train & set(sp["test"]))
        assert not set(sp["val"]) & set(sp["test"])
    held = set(splits["open_set"]["open_val_actors"]) | set(splits["open_set"]["open_test_actors"])
    assert not (held & set(splits["open_set"]["kept"]))
    assert held | set(splits["open_set"]["kept"]) == set(manifest["actors"])


def test_time_forward_split_is_group_aware_and_ordered():
    items = [{"g": "a", "ts": 3}, {"g": "b", "ts": 1}, {"g": "c", "ts": 2},
             {"g": "a", "ts": 4}, {"g": "d", "ts": 5}, {"g": "e", "ts": 6},
             {"g": "f", "ts": 7}]
    sp = time_forward_split(items, "ts", "g", test_frac=0.2, val_frac=0.2)
    assert sp["test"] == ["f"] and sp["val"] == ["e"]
    assert set(sp["train"]) == {"b", "c", "a", "d"}
    assert sp["cut_test"] == 7 and sp["cut_val"] == 6


def test_open_set_split_disjoint_and_seeded():
    actors = [f"a{i}" for i in range(10)]
    s1 = open_set_actor_split(actors, 0.2, seed=1)
    s2 = open_set_actor_split(actors, 0.2, seed=1)
    s3 = open_set_actor_split(actors, 0.2, seed=2)
    assert s1 == s2
    assert len(s1["open_val_actors"]) == 1 and len(s1["open_test_actors"]) == 1
    assert not (set(s1["open_val_actors"]) & set(s1["open_test_actors"]))
    assert set(s1["kept"]) | set(s1["open_val_actors"]) | set(s1["open_test_actors"]) == set(actors)
    assert (s1["open_test_actors"] != s3["open_test_actors"]
            or s1["open_val_actors"] != s3["open_val_actors"])
