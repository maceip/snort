"""Focused checks for DepImpact-style reconstruction stitched across windows."""

from snort.explain import TemporalGraph, reconstruct, WINDOW_S


def chain_graph():
    g = TemporalGraph()
    # entry -> mid -> exit, with anomaly concentrated on mid.
    g.add_edge("entry", "mid", ts=1000.0, anomaly=0.1, action="fork")
    g.add_edge("mid", "exit", ts=1100.0, anomaly=0.9, action="exec")
    g.node_anomaly["mid"] = 0.9
    return g


def test_finds_entry_and_exit():
    g = chain_graph()
    res = reconstruct(g, ["mid"], anchor_ts=1050.0)
    assert res.entry == "entry", res.entry
    assert res.exit == "exit", res.exit
    assert set(res.nodes) == {"entry", "mid", "exit"}
    assert len(res.edges) == 2


def test_stitches_across_windows():
    g = TemporalGraph()
    # Three hops spaced > 15 min apart: ORTHRUS single-window would miss them.
    g.add_edge("n0", "n1", ts=0.0, anomaly=0.2, action="fork")
    g.add_edge("n1", "n2", ts=WINDOW_S + 10, anomaly=0.4, action="exec")
    g.add_edge("n2", "n3", ts=2 * WINDOW_S + 20, anomaly=0.9, action="connect")
    res = reconstruct(g, ["n1"], anchor_ts=WINDOW_S)
    assert "n0" in res.nodes and "n3" in res.nodes, res.nodes
    assert len(res.windows_touched) >= 3, res.windows_touched


def test_horizon_bounds_stitching():
    g = TemporalGraph()
    g.add_edge("far", "mid", ts=0.0, anomaly=0.9, action="fork")
    g.add_edge("mid", "out", ts=100.0, anomaly=0.1, action="exec")
    res = reconstruct(g, ["mid"], anchor_ts=100.0, horizon_s=50.0)
    assert "far" not in res.nodes, res.nodes
    assert "out" in res.nodes


def test_cycle_does_not_hang_and_keeps_dag():
    g = TemporalGraph()
    g.add_edge("a", "b", ts=1.0, action="fork")
    g.add_edge("b", "c", ts=2.0, action="exec")
    g.add_edge("c", "a", ts=3.0, action="fork")  # back edge
    res = reconstruct(g, ["b"], anchor_ts=2.0)
    assert "b" in res.nodes
    assert len(res.edges) <= 2  # one edge dropped to keep the DAG


def test_empty_seeds():
    res = reconstruct(TemporalGraph(), [])
    assert res.nodes == [] and res.entry is None and res.exit is None


def test_edge_rarity_orders_work():
    g = TemporalGraph()
    for _ in range(9):
        g.add_edge("x", "common", ts=1.0, action="read")
    g.add_edge("x", "rare", ts=2.0, action="exec")
    order = g._window_edge_order(list(range(len(g.edges))))
    assert g.edges[order[0]].dst == "rare"


if __name__ == "__main__":
    for name, fn in sorted({k: v for k, v in globals().items() if k.startswith("test_")}.items()):
        fn()
        print(f"PASS {name}")
