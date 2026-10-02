"""E3-CADETS converter: edge/node exports + per-attack ground truth -> outputs.

Inputs (CSV or Parquet; export once from the restored Postgres dump, e.g.
`COPY (SELECT ...) TO 'edges.csv CSV HEADER`):
  edges:   edge_id, ts, host, src_id, dst_id, action[, src_type, dst_type]
           ts is integer nanoseconds, or an ISO-8601 timestamp.
  nodes:   node_id, node_type, name            (optional, enriches raw only)
  ground_truth_dir: one CSV per attack with a node_id column
           (ORTHRUS per-attack node lists); stem = incident id.
  ancestry: child,parent[,image]               (optional process tree; without
           it each subject forms its own trace root, see assembler)
  campaign_map: JSON {incident_id: campaign}   (optional; default maps the
           Drakon Nginx_Backdoor_06/12/13 attacks to campaign "drakon")

Outputs in out_dir: events.parquet, traces.parquet, manifest.json, splits.json.
"""

from __future__ import annotations

import argparse
import json
import os
import re

from lab.convert import event_schema as es
from lab.convert.splits import time_forward_split
from snort.trace import assembler

SOURCE_ID = "e3-cadets"
DRAKON = re.compile(r"nginx_backdoor_0[6].*|nginx_backdoor_1[23]", re.IGNORECASE)


def _read_table(path: str):
    import pandas as pd

    if path.endswith(".parquet"):
        return pd.read_parquet(path)
    return pd.read_csv(path)


def _to_ns(series):
    import pandas as pd

    if pd.api.types.is_numeric_dtype(series):
        return series.astype("int64")
    return (pd.to_datetime(series, utc=True).astype("int64")).astype("int64")


def convert_e3(
    edges_path: str,
    out_dir: str,
    nodes_path: str | None = None,
    ground_truth_dir: str | None = None,
    ancestry_path: str | None = None,
    campaign_map_path: str | None = None,
) -> dict:
    import pandas as pd

    os.makedirs(out_dir, exist_ok=True)
    edges = _read_table(edges_path)
    for col in ("ts", "host", "src_id", "dst_id", "action"):
        if col not in edges.columns:
            raise ValueError(f"edges table missing required column: {col}")
    edges = edges.copy()
    edges["ts"] = _to_ns(edges["ts"])
    edges = edges.sort_values("ts").reset_index(drop=True)
    edges["source_seq"] = edges.index.astype("int64")

    nodes = {}
    if nodes_path:
        for rec in _read_table(nodes_path).to_dict("records"):
            nodes[str(rec["node_id"])] = {
                "node_type": rec.get("node_type", ""),
                "name": rec.get("name", ""),
            }

    erecs = []
    for r in edges.to_dict("records"):
        tpl_src = f"{r['action']} {nodes.get(str(r['dst_id']), {}).get('name', r['dst_id'])}"
        tpl = es.template_hash_for_text(tpl_src)
        seq = int(r["source_seq"])
        erecs.append(
            {
                "ts": int(r["ts"]),
                "host": str(r["host"]),
                "source_id": SOURCE_ID,
                "source_seq": seq,
                "ingest_ts": int(r["ts"]),
                "subject": str(r["src_id"]),
                "object": str(r["dst_id"]),
                "action": str(r["action"]),
                "template_hash": tpl,
                "event_hash": es.canonical_event_hash(
                    int(r["ts"]), str(r["host"]), SOURCE_ID, seq,
                    str(r["src_id"]), str(r["dst_id"]), str(r["action"]), tpl,
                ),
                "raw": json.dumps(
                    {"edge_id": str(r.get("edge_id", seq)), **{k: str(v) for k, v in nodes.get(str(r["src_id"]), {}).items()}},
                    sort_keys=True,
                ),
            }
        )
    events = pd.DataFrame(erecs)

    parent_of, image_of = {}, {}
    if ancestry_path:
        for r in _read_table(ancestry_path).to_dict("records"):
            parent_of[str(r["child"])] = str(r["parent"])
            if "image" in r and pd.notna(r["image"]):
                image_of[str(r["child"])] = str(r["image"])
    traces = assembler.build_process_subtree_traces(events, parent_of, image_of)

    campaign_map = {}
    if campaign_map_path:
        campaign_map = es.load_json(campaign_map_path)
    incidents: list[dict] = []
    attack_nodes: dict[str, set] = {}
    if ground_truth_dir:
        for fn in sorted(os.listdir(ground_truth_dir)):
            if not fn.endswith(".csv"):
                continue
            iid = fn[: -len(".csv")]
            gt = _read_table(os.path.join(ground_truth_dir, fn))
            if "node_id" not in gt.columns:
                raise ValueError(f"{fn}: ground-truth CSV needs a node_id column")
            ids = {str(v) for v in gt["node_id"].tolist()}
            attack_nodes[iid] = ids
            camp = campaign_map.get(iid)
            if camp is None:
                camp = "drakon" if DRAKON.search(iid) else "unknown"
            incidents.append(
                {"incident_id": iid, "campaign": camp, "n_attack_nodes": len(ids),
                 "attack_nodes": sorted(ids)}
            )
    manifest = {
        "dataset": SOURCE_ID,
        "n_events": len(events),
        "n_traces": len(traces),
        "trace_rule": "process-subtree-under-session-root",
        "incidents": incidents,
        "campaigns": sorted({i["campaign"] for i in incidents}),
    }

    # Time-forward, group-aware split at incident granularity: each
    # incident is ordered by its earliest attack event.
    items = []
    for inc in incidents:
        nodes = attack_nodes[inc["incident_id"]]
        hit = events[events["subject"].isin(nodes) | events["object"].isin(nodes)]
        first = int(hit["ts"].min()) if len(hit) else int(events["ts"].max())
        items.append({"incident_id": inc["incident_id"], "ts": first})
    manifest_splits = time_forward_split(items, "ts", "incident_id", test_frac=0.34, val_frac=0.0) if items else {}

    es.to_parquet(events, os.path.join(out_dir, "events.parquet"))
    es.to_parquet(traces, os.path.join(out_dir, "traces.parquet"))
    es.to_lance(events, os.path.join(out_dir, "events.lance"))
    es.to_lance(traces, os.path.join(out_dir, "traces.lance"))
    es.dump_json(manifest, os.path.join(out_dir, "manifest.json"))
    es.dump_json({"split": "incident-time-forward", **manifest_splits},
                 os.path.join(out_dir, "splits.json"))
    return {"events": len(events), "traces": len(traces),
            "incidents": len(incidents), "out_dir": out_dir}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--edges", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--nodes", default=None)
    ap.add_argument("--ground-truth-dir", default=None)
    ap.add_argument("--ancestry", default=None)
    ap.add_argument("--campaign-map", default=None)
    a = ap.parse_args()
    print(convert_e3(a.edges, a.out_dir, a.nodes, a.ground_truth_dir,
                     a.ancestry, a.campaign_map))


if __name__ == "__main__":
    main()
