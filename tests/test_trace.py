"""Subsystem 2: Trace Assembly, Windowing & Feature Extraction."""

from snort.trace.assembler import Trace, TraceAssembler, anchor_for_event
from snort.trace.features import EdgeTransitionScorer, MergeableTraceFeatures


def test_trace_subsystem_lifecycle_and_features():
    """Verify trace anchoring, sliding window sealing, VELOX edge scoring, and MinHash features."""
    # 1. Anchor resolution across event schemas
    assert (
        anchor_for_event({"host": "host-1", "session_id": "sess-99"})
        == "session:host-1:sess-99"
    )
    assert anchor_for_event({"host": "host-2", "root_pid": 1337}) == "host:host-2:1337"
    assert anchor_for_event({"host": "host-3", "subject": 42}) == "host:host-3:42"

    # 2. Trace Assembler with sliding idle timeouts and session windowing
    assembler = TraceAssembler(idle_timeout_s=60, max_duration_s=3600)

    # Ingest events for session 1
    e1 = {
        "ts": 1000.0,
        "host": "srv-1",
        "session_id": "sess-alpha",
        "action": "fork",
        "tokens": ["bash", "spawn"],
        "technique_ids": ["T1059.004"],
        "indicators": {"ip": ["192.168.1.100"]},
    }
    assembler.ingest(e1)

    e2 = {
        "ts": 1020.0,
        "host": "srv-1",
        "session_id": "sess-alpha",
        "action": "exec",
        "tokens": ["wget", "download", "implant"],
        "technique_ids": ["T1105"],
        "indicators": {"ip": ["192.168.1.100"], "domain": ["malicious.site"]},
    }
    assembler.ingest(e2)

    # Ingest event for different session
    e3 = {
        "ts": 1030.0,
        "host": "srv-1",
        "session_id": "sess-beta",
        "action": "query",
        "tokens": ["dns", "lookup"],
    }
    assembler.ingest(e3)

    assert len(assembler.open_traces) == 2
    t_alpha = assembler.get("session:srv-1:sess-alpha:0")
    assert t_alpha is not None
    assert t_alpha.event_count == 2
    assert t_alpha.duration == 20.0

    # Idle timeout triggers window seal: event arriving after 1000s idle gap seals window 0 into window 1
    e4_late = {
        "ts": 2500.0,
        "host": "srv-1",
        "session_id": "sess-alpha",
        "action": "exec",
        "tokens": ["persist", "cron"],
    }
    t_alpha_new = assembler.ingest(e4_late)
    assert t_alpha_new.trace_id == "session:srv-1:sess-alpha:1"
    assert len(assembler.sealed_traces) == 1

    # Remaining traces sealed on idle threshold
    sealed = assembler.seal_idle(10000.0)
    assert len(sealed) == 2
    assert assembler.open_traces == []

    # Serialization round-trip
    d = t_alpha.to_dict()
    restored = Trace.from_dict(d)
    assert restored.trace_id == t_alpha.trace_id
    assert restored.features == t_alpha.features

    # 3. MergeableTraceFeatures & VELOX edge transition anomaly scoring
    scorer = EdgeTransitionScorer()
    common_score = scorer.score_edge("process", "fork", "process")
    assert common_score <= 0.05
    suspicious_score = scorer.score_edge("process", "inject", "process")
    assert suspicious_score >= 0.90

    feats = MergeableTraceFeatures()
    # Normal transition
    feats.add_event(
        event={
            "action": "fork",
            "subject": "proc1",
            "object": "proc2",
            "tokens": ["fork", "proc"],
        }
    )
    assert feats.anomalous_edge_count == 0

    # Rare anomaly transition (e.g. process -> inject -> process)
    feats.add_event(
        event={
            "action": "inject",
            "subject": "proc1",
            "object": "proc2",
            "tokens": ["inject", "shellcode"],
        }
    )
    assert feats.anomalous_edge_count == 1
    assert feats.edge_anomaly_score >= 0.90

    # 4. MinHash Jaccard similarity and merge associativity
    f_left = MergeableTraceFeatures()
    f_left.add_event(event={"ts": 0, "tokens": ["tokenA", "tokenB"]})
    f_right = MergeableTraceFeatures()
    f_right.add_event(event={"ts": 10, "tokens": ["tokenC"]})

    f_seq = MergeableTraceFeatures()
    f_seq.add_event(event={"ts": 0, "tokens": ["tokenA", "tokenB"]})
    f_seq.add_event(event={"ts": 10, "tokens": ["tokenC"]})

    f_merged = f_left.merge(f_right)
    assert f_merged.minhash_jaccard(f_seq) == 1.0
    assert f_merged.event_count == 2
    assert f_merged.duration == 10.0
