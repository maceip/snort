import math

from snort.trace.assembler import TraceAssembler, anchor_for_event
from snort.trace.features import MergeableTraceFeatures


def ev(ts, tokens, host="h1", techniques=(), indicators=None, **kw):
    e = {"ts": ts, "host": host, "tokens": tokens, "technique_ids": list(techniques)}
    if indicators:
        e["indicators"] = indicators
    e.update(kw)
    return e


def test_token_and_bigram_counts():
    f = MergeableTraceFeatures()
    f.add_event(event=ev(0, ["a", "b", "a"]))
    assert f.token_counts == {"a": 2, "b": 1}
    assert f.bigram_counts == {"a\x00b": 1, "b\x00a": 1}
    assert f.event_count == 1
    assert math.isclose(f.log_token_counts()["a"], math.log1p(2))


def test_minhash_identical_vs_disjoint():
    a = MergeableTraceFeatures()
    b = MergeableTraceFeatures()
    c = MergeableTraceFeatures()
    a.add_event(event=ev(0, ["cmd", "exec", "file"]))
    b.add_event(event=ev(0, ["cmd", "exec", "file"]))
    c.add_event(event=ev(0, ["zzz", "qqq", "www"]))
    assert a.minhash_jaccard(b) == 1.0
    assert a.minhash_jaccard(c) < 0.3


def test_duration_event_count_and_merge_equals_sequential():
    seq = MergeableTraceFeatures()
    events = [ev(ts, [f"tok{k % 3}"]) for k, ts in enumerate((0, 10, 25))]
    for e in events:
        seq.add_event(event=e)
    assert seq.event_count == 3
    assert seq.duration == 25
    left = MergeableTraceFeatures()
    right = MergeableTraceFeatures()
    left.add_event(event=events[0])
    for e in events[1:]:
        right.add_event(event=e)
    merged = left.merge(right)
    assert merged == seq


def test_technique_tags_and_indicators_merge():
    a = MergeableTraceFeatures()
    b = MergeableTraceFeatures()
    a.add_event(event=ev(0, ["x"], techniques=["T1059"], indicators={"domain": "a.example"}))
    b.add_event(event=ev(1, ["y"], techniques=["T1071"], indicators={"domain": "b.example", "ip": "1.2.3.4"}))
    m = a.merge(b)
    assert m.technique_tags == {"T1059", "T1071"}
    assert m.indicators == {"domain": {"a.example", "b.example"}, "ip": {"1.2.3.4"}}


def test_assembler_anchors_idle_and_rolling():
    asm = TraceAssembler(idle_timeout_s=60, max_duration_s=3600)
    asm.ingest(ev(0, ["a"], session_id="s1"))
    asm.ingest(ev(10, ["b"], session_id="s1"))
    asm.ingest(ev(20, ["c"], session_id="s2"))
    assert len(asm.open_traces) == 2
    t = asm.get("session:h1:s1:0")
    assert t is not None and t.event_count == 2 and t.duration == 10
    # idle gap seals s1 into a new window
    t2 = asm.ingest(ev(1000, ["d"], session_id="s1"))
    assert t2.trace_id == "session:h1:s1:1"
    assert len(asm.sealed_traces) == 1
    # seal_idle seals the rest
    assert len(asm.seal_idle(5000)) == 2
    assert asm.open_traces == []


def test_assembler_host_anchor_and_serialization():
    asm = TraceAssembler()
    assert anchor_for_event({"host": "h", "root_pid": 42}) == "host:h:42"
    tr = asm.ingest(ev(5, ["a"], host="h", root_pid=42, technique_ids=["T1059"]))
    d = tr.to_dict()
    from snort.trace.assembler import Trace

    back = Trace.from_dict(d)
    assert back.trace_id == tr.trace_id and back.features == tr.features
