"""Subsystem 7: Causal DAG Reconstruction, DepImpact Multi-Window Slicing & Provenance."""

from snort.explain import TemporalGraph, reconstruct, WINDOW_S, HORIZON_S


def test_reconstruction_subsystem_causal_dag():
    """Verify DepImpact-style causal DAG reconstruction across windows, cycle breaking, and rarity ordering."""
    # 1. Multi-hop chain across 15-minute window boundaries (stitching across windows)
    g = TemporalGraph()
    # Node 0 (Initial entry: fork) at t=0
    g.add_edge("entry_proc", "middle_proc", ts=0.0, anomaly=0.2, action="fork")
    # Node 1 -> Node 2 in Window 2 (t > WINDOW_S)
    g.add_edge(
        "middle_proc", "recon_tool", ts=WINDOW_S + 30.0, anomaly=0.5, action="exec"
    )
    # Node 2 -> Node 3 in Window 3 (t > 2 * WINDOW_S)
    g.add_edge(
        "recon_tool",
        "c2_socket",
        ts=2 * WINDOW_S + 60.0,
        anomaly=0.95,
        action="connect",
    )
    g.node_anomaly["recon_tool"] = 0.90

    # Slicing from middle_proc
    result = reconstruct(g, seeds=["middle_proc"], anchor_ts=WINDOW_S)
    assert result.entry == "entry_proc"
    assert result.exit == "c2_socket"
    assert "entry_proc" in result.nodes
    assert "c2_socket" in result.nodes
    assert len(result.windows_touched) >= 3

    # 2. Cycle handling (provenance loops do not hang and maintain DAG property)
    cyclic_graph = TemporalGraph()
    cyclic_graph.add_edge("proc_a", "proc_b", ts=10.0, action="fork")
    cyclic_graph.add_edge("proc_b", "proc_c", ts=20.0, action="exec")
    cyclic_graph.add_edge("proc_c", "proc_a", ts=30.0, action="fork")  # cycle back-edge

    cycle_res = reconstruct(cyclic_graph, seeds=["proc_b"], anchor_ts=20.0)
    assert "proc_b" in cycle_res.nodes
    # Back-edge was dropped to preserve DAG
    assert len(cycle_res.edges) <= 2

    # 3. Horizon bounds check (edges older than horizon are excluded)
    bounded_graph = TemporalGraph()
    bounded_graph.add_edge(
        "ancient_ancestry", "seed_proc", ts=0.0, anomaly=0.8, action="fork"
    )
    bounded_graph.add_edge(
        "seed_proc", "local_file", ts=HORIZON_S + 1000.0, anomaly=0.1, action="write"
    )

    bound_res = reconstruct(
        bounded_graph,
        seeds=["seed_proc"],
        anchor_ts=HORIZON_S + 1000.0,
        horizon_s=500.0,
    )
    assert "ancient_ancestry" not in bound_res.nodes
    assert "local_file" in bound_res.nodes

    # 4. Edge rarity ordering prioritizes rare security actions over high-frequency reads
    rarity_graph = TemporalGraph()
    for _ in range(20):
        rarity_graph.add_edge("daemon", "common_cfg", ts=5.0, action="read")
    rarity_graph.add_edge("daemon", "rare_exploit", ts=6.0, action="inject")

    edge_order = rarity_graph._window_edge_order(list(range(len(rarity_graph.edges))))
    assert rarity_graph.edges[edge_order[0]].dst == "rare_exploit"
