"""Go/no-go 1, trace boundaries (plan sec 8, weeks 1-2).

Question: does the version-1 trace definition keep each attack in a few pure
traces? Inputs: events.parquet, traces.parquet, manifest.json from the
E3-CADETS converter.

Per incident: rank traces by attack-node count; take the top-K (K=3);
coverage = share of the incident's attack nodes inside those traces;
purity = share of events in those traces that touch an attack node.
PASS needs coverage >= 0.8 and purity >= 0.5.

Cut-offs are fixed here, before looking at results (plan requirement).
Overall verdict is GO only if every incident passes.
"""

from __future__ import annotations

import argparse
import json

# Fixed before looking at results: "mostly into 3 or fewer traces" and
# "those traces are mostly attack activity".
MAX_TRACES = 3
MIN_COVERAGE = 0.8
MIN_PURITY = 0.5


def evaluate_boundaries(events, traces, manifest: dict,
                        max_traces: int = MAX_TRACES,
                        min_coverage: float = MIN_COVERAGE,
                        min_purity: float = MIN_PURITY) -> dict:
    import json as _json

    trace_of_event = {}
    for t in traces.to_dict("records"):
        for h in _json.loads(t["event_hashes"]):
            trace_of_event[h] = t["trace_id"]
    trace_members: dict[str, set] = {}
    for h, tid in trace_of_event.items():
        trace_members.setdefault(tid, set()).add(h)
    attack_events: dict[str, set] = {}
    per_incident = []
    for inc in manifest.get("incidents", []):
        nodes = set(inc["attack_nodes"])
        ev = set(
            events.loc[events["subject"].isin(nodes) | events["object"].isin(nodes), "event_hash"]
        )
        attack_events[inc["incident_id"]] = ev
        # count attack NODES per trace via member events' endpoints
        ev_rows = events.set_index("event_hash")
        node_trace: dict[str, set] = {}
        for h in ev:
            tid = trace_of_event.get(h)
            if tid is None:
                continue
            row = ev_rows.loc[h]
            for n in (str(row["subject"]), str(row["object"])):
                if n in nodes:
                    node_trace.setdefault(tid, set()).add(n)
        ranked = sorted(node_trace.items(), key=lambda kv: (-len(kv[1]), kv[0]))
        top = ranked[:max_traces]
        top_ids = [t for t, _ in top]
        covered = set().union(*[v for _, v in top]) if top else set()
        coverage = len(covered) / len(nodes) if nodes else 1.0
        top_events = set().union(*[trace_members[t] for t in top_ids]) if top_ids else set()
        purity = len(ev & top_events) / len(top_events) if top_events else 0.0
        passed = bool(coverage >= min_coverage and purity >= min_purity)
        per_incident.append(
            {
                "incident_id": inc["incident_id"],
                "n_attack_nodes": len(nodes),
                "n_traces_with_attack_nodes": len(ranked),
                "top_traces": [
                    {"trace_id": t, "attack_nodes": len(v)} for t, v in top
                ],
                "coverage_top3": round(coverage, 4),
                "purity_top3": round(purity, 4),
                "pass": passed,
            }
        )
    overall = bool(per_incident) and all(p["pass"] for p in per_incident)
    return {
        "test": "go-no-go-1-trace-boundaries",
        "cutoffs": {"max_traces": max_traces, "min_coverage": min_coverage,
                    "min_purity": min_purity},
        "incidents": per_incident,
        "verdict": "GO" if overall else "NO-GO",
    }


def main() -> None:
    from lab.convert import event_schema as es

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--events", required=True)
    ap.add_argument("--traces", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    report = evaluate_boundaries(es.read_parquet(a.events), es.read_parquet(a.traces),
                                 es.load_json(a.manifest))
    print(json.dumps(report, indent=2))
    if a.out:
        es.dump_json(report, a.out)


if __name__ == "__main__":
    main()
