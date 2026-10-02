"""Provenance reconstruction: DepImpact-style, stitched across windows.

Reimplements ORTHRUS's DepImpact algorithm (``depimpact_utils.py``,
``component`` mode, ``degree_recon`` scoring) over the plan's temporal
graph, with the plan's addition: windows are stitched together. ORTHRUS
reconstructs inside a single 15-minute window; here backward/forward
traversal follows edges into adjacent windows until an entry/exit node is
found or the 48-hour horizon is reached (plan sections 4.5 and 2.1).

Entry nodes have no incoming edge in the reachable subgraph; exit nodes
have no outgoing edge. Each entry/exit is scored by criticality, the mean
of normalized out/in-degree and normalized anomaly (DepImpact's
``degree_recon`` option). The union of the critical dependency graphs is
reported. Edge rarity orders the work.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

WINDOW_S = 15 * 60
HORIZON_S = 48 * 3600


@dataclass(frozen=True)
class TemporalEdge:
    src: str
    dst: str
    ts: float
    anomaly: float = 0.0
    action: str = ""


@dataclass
class ReconstructionResult:
    seeds: List[str]
    nodes: List[str]
    edges: List[TemporalEdge]
    entry: Optional[str]
    exit: Optional[str]
    criticality: Dict[str, float]
    windows_touched: List[int]


class TemporalGraph:
    """In-memory temporal provenance graph (plan section 4.5: 48h horizon)."""

    def __init__(self) -> None:
        self.nodes: Set[str] = set()
        self.node_anomaly: Dict[str, float] = {}
        self.edges: List[TemporalEdge] = []
        self._out: Dict[str, List[int]] = defaultdict(list)
        self._in: Dict[str, List[int]] = defaultdict(list)
        self.action_counts: Counter = Counter()

    def add_node(self, node_id: str, anomaly: float = 0.0) -> None:
        self.nodes.add(node_id)
        self.node_anomaly[node_id] = max(self.node_anomaly.get(node_id, 0.0), anomaly)

    def add_edge(
        self,
        src: str,
        dst: str,
        ts: float,
        anomaly: float = 0.0,
        action: str = "",
    ) -> None:
        self.add_node(src)
        self.add_node(dst, anomaly)
        edge = TemporalEdge(src=src, dst=dst, ts=ts, anomaly=anomaly, action=action)
        idx = len(self.edges)
        self.edges.append(edge)
        self._out[src].append(idx)
        self._in[dst].append(idx)
        self.action_counts[action or edge.src + "->" + edge.dst] += 1
        self.node_anomaly[dst] = max(self.node_anomaly.get(dst, 0.0), anomaly)

    def window_of(self, ts: float) -> int:
        return int(ts // WINDOW_S)

    def edge_rarity(self, edge: TemporalEdge) -> float:
        """Rarity in (0, 1]: 1 for a never-repeated action, lower when common."""
        key = edge.action or edge.src + "->" + edge.dst
        count = self.action_counts.get(key, 1)
        return 1.0 / (1.0 + float(count - 1))

    def _window_edge_order(self, indices: Iterable[int]) -> List[int]:
        """Order edge work by rarity (rarest first), then timestamp."""
        return sorted(
            indices,
            key=lambda i: (-self.edge_rarity(self.edges[i]), self.edges[i].ts),
        )


def _to_dag(edges: Sequence[TemporalEdge]) -> List[TemporalEdge]:
    """Convert an edge list to a DAG ordered by time, dropping back edges.

    Mirrors DepImpact's versioned-DAG step: sort by timestamp and drop any
    edge that would close a cycle (union-find over nodes in time order).
    """
    parent: Dict[str, str] = {}

    def find(node: str) -> str:
        while parent.get(node, node) != node:
            parent[node] = parent.get(parent[node], parent[node])
            node = parent[node]
        return node

    dag: List[TemporalEdge] = []
    for edge in sorted(edges, key=lambda e: e.ts):
        root_src, root_dst = find(edge.src), find(edge.dst)
        if root_src == root_dst:
            continue  # back edge: would close a cycle
        parent[root_src] = root_dst
        dag.append(edge)
    return dag


def _reachable(
    graph: TemporalGraph,
    seeds: Sequence[str],
    direction: str,
    t_min: float,
    t_max: float,
) -> Tuple[Set[str], List[TemporalEdge]]:
    """BFS from seeds along in-edges (backward) or out-edges (forward).

    Traversal is window-stitched: it follows edges across adjacent 15-minute
    windows anywhere inside the [t_min, t_max] horizon. Within each
    frontier, edges are expanded rarest-first so rare (attack-relevant)
    paths are found first.
    """
    seen: Set[str] = set(seeds)
    found_edges: List[TemporalEdge] = []
    queue: deque = deque(seeds)
    adjacency = graph._in if direction == "backward" else graph._out
    while queue:
        node = queue.popleft()
        candidates = [
            i
            for i in adjacency.get(node, [])
            if t_min <= graph.edges[i].ts <= t_max
        ]
        for i in graph._window_edge_order(candidates):
            edge = graph.edges[i]
            nxt = edge.src if direction == "backward" else edge.dst
            if edge not in found_edges:
                found_edges.append(edge)
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return seen, found_edges


def _criticality(
    graph: TemporalGraph,
    nodes: Set[str],
    edges: Sequence[TemporalEdge],
) -> Dict[str, float]:
    """DepImpact ``degree_recon``: mean of normalized out/in-degree and anomaly."""
    out_degree: Counter = Counter()
    in_degree: Counter = Counter()
    for edge in edges:
        if edge.src in nodes:
            out_degree[edge.src] += 1
        if edge.dst in nodes:
            in_degree[edge.dst] += 1
    max_out = max(list(out_degree.values()) + [1])
    max_in = max(list(in_degree.values()) + [1])
    max_anomaly = max([graph.node_anomaly.get(n, 0.0) for n in nodes] + [1.0])
    scores: Dict[str, float] = {}
    for node in nodes:
        degree_term = 0.5 * (out_degree.get(node, 0) / max_out + in_degree.get(node, 0) / max_in)
        anomaly_term = graph.node_anomaly.get(node, 0.0) / max_anomaly
        scores[node] = 0.5 * (degree_term + anomaly_term)
    return scores


def reconstruct(
    graph: TemporalGraph,
    seeds: Sequence[str],
    anchor_ts: Optional[float] = None,
    horizon_s: float = HORIZON_S,
) -> ReconstructionResult:
    """Backward/forward DepImpact-style reconstruction stitched across windows.

    Starts from ``seeds`` (group members / flagged nodes), traces back to
    entry nodes and forward to exit nodes across adjacent 15-minute windows
    up to ``horizon_s`` (default 48h), scores entries/exits by criticality,
    and reports the union of the critical dependency graphs.
    """
    seeds = list(seeds)
    if not seeds:
        return ReconstructionResult(
            seeds=[], nodes=[], edges=[],
            entry=None, exit=None, criticality={}, windows_touched=[],
        )
    if anchor_ts is None:
        stamps = [e.ts for e in graph.edges if e.src in set(seeds) or e.dst in set(seeds)]
        anchor_ts = min(stamps) if stamps else 0.0
    t_min = anchor_ts - horizon_s
    t_max = anchor_ts + horizon_s

    back_nodes, back_edges = _reachable(graph, seeds, "backward", t_min, t_max)
    fwd_nodes, fwd_edges = _reachable(graph, seeds, "forward", t_min, t_max)
    all_nodes = back_nodes | fwd_nodes
    dag_edges = _to_dag(list(back_edges + fwd_edges))

    in_sub: Counter = Counter()
    out_sub: Counter = Counter()
    for edge in dag_edges:
        out_sub[edge.src] += 1
        in_sub[edge.dst] += 1
    entries = sorted([n for n in all_nodes if in_sub.get(n, 0) == 0])
    exits = sorted([n for n in all_nodes if out_sub.get(n, 0) == 0])

    scores = _criticality(graph, all_nodes, dag_edges)
    entry = max(entries, key=lambda n: (scores.get(n, 0.0), n)) if entries else None
    exit_node = max(exits, key=lambda n: (scores.get(n, 0.0), n)) if exits else None

    # Union of the critical dependency graphs: keep DAG edges touching a
    # path through the chosen entry/exit; fall back to the full DAG.
    keep: Set[int] = set()
    if entry is not None or exit_node is not None:
        targets = {t for t in (entry, exit_node) if t is not None} | set(seeds)
        dag_out: Dict[str, List[int]] = defaultdict(list)
        for i, edge in enumerate(dag_edges):
            dag_out[edge.src].append(i)
        stack = [entry] if entry is not None else list(seeds)
        visited: Set[str] = set()
        while stack:
            node = stack.pop()
            if node in visited:
                continue
            visited.add(node)
            for i in dag_out.get(node, []):
                keep.add(i)
                if dag_edges[i].dst not in visited:
                    stack.append(dag_edges[i].dst)
        if not keep:
            keep = set(range(len(dag_edges)))
    else:
        keep = set(range(len(dag_edges)))
    kept_edges = [dag_edges[i] for i in sorted(keep)]
    kept_nodes = sorted({n for e in kept_edges for n in (e.src, e.dst)} | set(seeds))
    windows = sorted({graph.window_of(e.ts) for e in kept_edges})
    return ReconstructionResult(
        seeds=seeds,
        nodes=kept_nodes,
        edges=kept_edges,
        entry=entry,
        exit=exit_node,
        criticality={n: scores.get(n, 0.0) for n in kept_nodes},
        windows_touched=windows,
    )
