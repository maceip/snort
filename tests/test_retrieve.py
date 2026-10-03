"""Subsystem 3: Candidate Retrieval, DynaHash LSH, BlockingPy ANN & Indicator Inversion."""

from snort.retrieve.candidates import ANNBlocker, CandidateRetriever
from snort.retrieve.indicators import IndicatorIndex
from snort.retrieve.minhash_lsh import MinHashLSHIndex
from snort.retrieve.provenance import ProvenanceGraph
from snort.trace.signatures import Trace


def make_test_trace(
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


def test_retrieve_subsystem_blocking_and_indexing():
    """Verify DynaHash BK-Tree multi-probe, ANN feature blocker, IndicatorIndex, and CandidateRetriever capping."""
    # 1. DynaHash Banded LSH + BK-Tree Multi-Probe
    lsh = MinHashLSHIndex(theta=0.5, multi_probe=True)
    base_tokens = [f"cmd_{i}" for i in range(25)]
    t_base = make_test_trace("base", base_tokens)
    lsh.insert("base", t_base.signature)

    # Near duplicate (shares 23 of 25 tokens)
    near_tokens = base_tokens[:23] + ["cmd_diff1", "cmd_diff2"]
    t_near = make_test_trace("near", near_tokens)
    lsh.insert("near", t_near.signature)

    # Completely disjoint
    far_tokens = [f"foreign_{i}" for i in range(25)]
    t_far = make_test_trace("far", far_tokens)
    lsh.insert("far", t_far.signature)

    hits = dict(lsh.query(t_base.signature, exclude="base"))
    assert "near" in hits
    assert hits["near"] > hits.get("far", 0.0)

    # 2. Indicator Index Inverted Lookups
    ind_idx = IndicatorIndex()
    ind_idx.add("trace_with_ip", frozenset(["ip:192.168.1.50", "domain:c2.bad"]))
    ind_idx.add("trace_with_domain", frozenset(["domain:c2.bad"]))
    ind_idx.add("benign_trace", frozenset(["domain:google.com"]))

    ind_hits = ind_idx.query(frozenset(["ip:192.168.1.50", "domain:c2.bad"]))
    assert "trace_with_ip" in ind_hits
    assert ind_hits["trace_with_ip"] == 2
    assert "trace_with_domain" in ind_hits
    assert ind_hits["trace_with_domain"] == 1
    assert "benign_trace" not in ind_hits

    # 3. BlockingPy ANN Continuous Feature Blocker
    ann = ANNBlocker(top_k=5)
    ann.add("trace_ann_similar", [10.0, 2.5, 1.2, 0.0])
    ann.add("trace_ann_distant", [5000.0, 0.0, 0.0, 10.0])
    ann_hits = ann.query([10.2, 2.4, 1.1, 0.0])
    assert len(ann_hits) >= 1
    assert ann_hits[0][0] == "trace_ann_similar"
    assert ann_hits[0][1] > 0.95

    # 4. End-to-End CandidateRetriever with Hard Bounded Capping (k <= 50)
    retriever = CandidateRetriever(
        lsh=MinHashLSHIndex(theta=0.3, multi_probe=True),
        indicators=IndicatorIndex(),
        provenance=ProvenanceGraph(),
        ann=ANNBlocker(top_k=20),
        max_candidates=10,  # test capping threshold
    )

    # Index 20 target traces
    for i in range(20):
        t_i = make_test_trace(
            f"target_{i}",
            tokens=[f"cmd_{i % 5}", f"sub_{i % 3}"],
            indicators=frozenset(["shared_ioc:10.0.0.1"]),
            entities=frozenset([f"entity_{i % 2}"]),
        )
        retriever.index_trace(t_i)

    query_trace = make_test_trace(
        "query_1",
        tokens=["cmd_0", "sub_0"],
        indicators=frozenset(["shared_ioc:10.0.0.1"]),
        entities=frozenset(["entity_0"]),
    )
    candidates = retriever.retrieve(query_trace)

    # Verify hard cap is enforced
    assert len(candidates) <= 10
    # Verify candidate properties
    assert all(c.trace_id != "query_1" for c in candidates)
    assert any("indicator" in c.sources for c in candidates)
    assert any(c.estimate > 0.0 for c in candidates)


def test_multi_probe_handles_deep_trees_and_compacts_evicted_keys():
    deep = MinHashLSHIndex(num_perm=4, max_vectors=1100)
    for i in range(1100):
        deep.insert(str(i), (i, i, i, i))
    assert dict(deep.query((1099, 1099, 1099, 1099)))["1099"] == 1.0

    bounded = MinHashLSHIndex(num_perm=4, max_vectors=2)
    for i in range(100):
        bounded.insert(str(i), (i, i, i, i))
        assert len(bounded) <= 2
        assert all(len(tree.nodes) <= 4 for tree in bounded._trees)
    assert dict(bounded.query((99, 99, 99, 99)))["99"] == 1.0
    assert "0" not in dict(bounded.query((0, 0, 0, 0)))


def test_dense_candidates_use_matching_trace_duration():
    retriever = CandidateRetriever(
        MinHashLSHIndex(), IndicatorIndex(), ProvenanceGraph()
    )
    longer = Trace("longer", tokens=("a", "b"), start_ts=100, end_ts=110)
    shorter = Trace("shorter", tokens=("a", "b"), start_ts=100, end_ts=100)
    retriever.index_trace(longer)
    retriever.index_trace(shorter)
    query = Trace("query", tokens=("a", "b"), start_ts=100, end_ts=109)
    candidates = {c.trace_id: c for c in retriever.retrieve(query)}
    assert "ann" in candidates["longer"].sources
    assert "ann" not in candidates["shorter"].sources
