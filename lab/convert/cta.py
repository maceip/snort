"""CTA corpus converter: data_with_sclc.json -> Event Parquet + manifest + splits.

Input record fields (aliases tolerated, first hit wins):
  actor:   actor | actor_name | label
  session: session_id | beacon_id | beacon | session
  ts:      timestamp | ts | time        (ns int, seconds int/float, or ISO-8601)
  text:    command | text | cmd
  kind:    type | cmd_type              (defaults to EXEC)
  tactic:  tactic | technique           (kept in raw + manifest)

Author-faithful preprocessing (docs/assessment/unveiling-ctas.md), on by default:
  --no-sf-merge disables merging actors whose names contain plki/joke into sf;
  --keep-other keeps the wrongly-labelled `other` class;
  --keep-long disables dropping sessions over 256 tokens.

Event mapping: one row per command; host = actor (pseudo-host, so per-actor
analysis needs no join); subject = session id; object = command text
truncated to 512 chars; action = command kind. The full text also rides along
in the extra raw_text column for trace features.

Outputs in out_dir: events.parquet, traces.parquet, manifest.json, splits.json.
splits.json holds per-actor time-forward 70/15/15 session splits plus the
open-set held-out actors (20%, disjoint val/test halves).
"""

from __future__ import annotations

import argparse
import json
import os

from lab.convert import event_schema as es
from lab.convert.splits import open_set_actor_split, time_forward_split
from snort.trace import assembler

SOURCE_ID = "cta"
MAX_TOKENS = 256


def _first(d: dict, keys: list[str], default=None):
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


def _to_ns(v) -> int:
    import pandas as pd

    if isinstance(v, (int, float)):
        f = float(v)
        return int(f) if f > 1e12 else int(f * 1_000_000_000)
    return int(pd.to_datetime(v, utc=True).value)


def load_records(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        obj = json.load(fh)
    if isinstance(obj, dict):
        for key in ("commands", "data", "sessions", "records"):
            if isinstance(obj.get(key), list):
                return obj[key]
        raise ValueError(f"{path}: JSON object has no record list key")
    if not isinstance(obj, list):
        raise ValueError(f"{path}: expected a JSON list of command records")
    return obj


def convert_cta(
    json_path: str,
    out_dir: str,
    apply_sf_merge: bool = True,
    drop_other: bool = True,
    drop_long_sessions: bool = True,
    test_frac: float = 0.15,
    val_frac: float = 0.15,
    holdout_frac: float = 0.2,
    seed: int = 42,
) -> dict:
    import pandas as pd

    os.makedirs(out_dir, exist_ok=True)
    norm = []
    for r in load_records(json_path):
        if not isinstance(r, dict):
            continue
        norm.append(
            {
                "actor": str(_first(r, ["actor", "actor_name", "label"], "unknown")),
                "session": str(_first(r, ["session_id", "beacon_id", "beacon", "session"], "")),
                "ts": _to_ns(_first(r, ["timestamp", "ts", "time"], 0)),
                "text": str(_first(r, ["command", "text", "cmd"], "")),
                "kind": str(_first(r, ["type", "cmd_type"], "EXEC")),
                "tactic": str(_first(r, ["tactic", "technique"], "")),
            }
        )
    norm = [r for r in norm if r["session"]]
    if not norm:
        raise ValueError("no usable command records (need at least a session id)")

    dropped_other = 0
    if drop_other:
        kept = [r for r in norm if r["actor"] != "other"]
        dropped_other = len(norm) - len(kept)
        norm = kept

    sf_merged = 0
    if apply_sf_merge:
        for r in norm:
            low = r["actor"].lower()
            if "plki" in low or "joke" in low:
                if r["actor"] != "sf":
                    sf_merged += 1
                r["actor"] = "sf"

    if drop_long_sessions:
        counts: dict[str, int] = {}
        for r in norm:
            counts[r["session"]] = counts.get(r["session"], 0) + len(r["text"].split())
        long_sessions = {s for s, c in counts.items() if c > MAX_TOKENS}
    else:
        long_sessions = set()
    dropped_long = sum(1 for r in norm if r["session"] in long_sessions)
    norm = [r for r in norm if r["session"] not in long_sessions]

    # sf is sampled to 1500 sessions, per the authors.
    sf_sessions = sorted({r["session"] for r in norm if r["actor"] == "sf"})
    dropped_sf_sample = 0
    if apply_sf_merge and len(sf_sessions) > 1500:
        keep = set(sf_sessions[:1500])
        before = len(norm)
        norm = [r for r in norm if r["actor"] != "sf" or r["session"] in keep]
        dropped_sf_sample = before - len(norm)

    norm.sort(key=lambda r: (r["ts"], r["session"], r["text"]))
    erecs = []
    for seq, r in enumerate(norm):
        tpl = es.template_hash_for_text(r["text"])
        erecs.append(
            {
                "ts": r["ts"],
                "host": r["actor"],
                "source_id": SOURCE_ID,
                "source_seq": seq,
                "ingest_ts": r["ts"],
                "subject": r["session"],
                "object": r["text"][:512],
                "action": r["kind"],
                "template_hash": tpl,
                "event_hash": es.canonical_event_hash(
                    r["ts"], r["actor"], SOURCE_ID, seq, r["session"],
                    r["text"][:512], r["kind"], tpl,
                ),
                "raw": json.dumps({"tactic": r["tactic"]}, sort_keys=True),
                "raw_text": r["text"],
            }
        )
    events = pd.DataFrame(erecs)
    traces = assembler.build_beacon_traces(events, session_col="subject")

    first_ts = events.groupby("subject")["ts"].min().to_dict()
    actor_of = events.groupby("subject")["host"].first().to_dict()
    session_items = [
        {"session_id": s, "actor": a, "ts": int(first_ts[s])} for s, a in actor_of.items()
    ]
    by_actor: dict[str, list[dict]] = {}
    for it in session_items:
        by_actor.setdefault(it["actor"], []).append(it)
    per_actor = {
        a: time_forward_split(v, "ts", "session_id", test_frac, val_frac)
        for a, v in by_actor.items()
    }
    open_set = open_set_actor_split(list(by_actor), holdout_frac, seed)

    manifest = {
        "dataset": SOURCE_ID,
        "n_commands": len(events),
        "n_sessions": len(traces),
        "n_actors": len(by_actor),
        "actors": sorted(by_actor),
        "sessions_per_actor": {a: len(v) for a, v in sorted(by_actor.items())},
        "t_start": int(events["ts"].min()),
        "t_end": int(events["ts"].max()),
        "preprocessing": {
            "sf_merge": apply_sf_merge,
            "sf_merged_commands": sf_merged,
            "dropped_other": dropped_other,
            "dropped_long_session_commands": dropped_long,
            "dropped_sf_sample_commands": dropped_sf_sample,
        },
    }
    es.to_parquet(events.drop(columns=["raw_text"]), os.path.join(out_dir, "events.parquet"))
    es.to_parquet(traces, os.path.join(out_dir, "traces.parquet"))
    es.dump_json(manifest, os.path.join(out_dir, "manifest.json"))
    es.dump_json({"per_actor_time_forward": per_actor, "open_set": open_set},
                 os.path.join(out_dir, "splits.json"))
    return {"commands": len(events), "sessions": len(traces),
            "actors": len(by_actor), "out_dir": out_dir}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--no-sf-merge", action="store_true")
    ap.add_argument("--keep-other", action="store_true")
    ap.add_argument("--keep-long", action="store_true")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    print(convert_cta(a.json, a.out_dir, not a.no_sf_merge,
                      not a.keep_other, not a.keep_long, seed=a.seed))


if __name__ == "__main__":
    main()
