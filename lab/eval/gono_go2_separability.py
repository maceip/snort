"""Go/no-go 2, separability (plan sec 8, weeks 1-2).

Question: does behavioural similarity separate same-attack pairs from
unrelated pairs on provenance data? Inputs: traces.parquet + manifest.json.

Scores: MinHash Jaccard (128 functions, 1-3-gram shingles) and TF-IDF cosine
(word 1-2-grams), per plan sec 4.2. Same-group pairs (shared incident, or
shared actor for CTA traces) against an equal number of seeded random pairs.
PASS: AUC >= 0.8 for at least one (cut-off fixed before looking at results).
"""

from __future__ import annotations

import argparse
import json
import random

PASS_AUC = 0.8


def _trace_groups(manifest: dict) -> dict[str, str]:
    """Map trace anchor -> group id from the manifest.

    E3 manifests list incidents with attack_nodes (node ids, not anchors), so
    group membership there is resolved by the caller-provided anchor map; CTA
    manifests map sessions to actors directly.
    """
    groups: dict[str, str] = {}
    for inc in manifest.get("incidents", []):
        for n in inc.get("attack_nodes", []):
            groups.setdefault(str(n), inc["incident_id"])
    return groups


def evaluate_separability(
    traces,
    trace_group: dict[str, str],
    n_pairs: int = 2000,
    seed: int = 42,
    pass_auc: float = PASS_AUC,
) -> dict:
    from snort.trace import features as F

    recs = traces.to_dict("records")
    ids = [r["trace_id"] for r in recs]
    texts = [r["text"] for r in recs]
    group_of = {r["trace_id"]: trace_group.get(r["trace_id"], r["trace_id"])
                for r in recs}
    by_group: dict[str, list[int]] = {}
    for i, tid in enumerate(ids):
        by_group.setdefault(group_of[tid], []).append(i)

    rng = random.Random(seed)
    same: list[tuple[int, int]] = []
    multi = [v for v in by_group.values() if len(v) >= 2]
    while multi and len(same) < n_pairs:
        v = rng.choice(multi)
        a, b = rng.sample(v, 2)
        same.append((min(a, b), max(a, b)))
    same = sorted(set(same))[:n_pairs]

    n = len(ids)
    rand: set[tuple[int, int]] = set()
    guard = 0
    while len(rand) < len(same) and guard < 10 * max(len(same), 1) + 100:
        guard += 1
        a, b = rng.randrange(n), rng.randrange(n)
        if a == b or group_of[ids[a]] == group_of[ids[b]]:
            continue
        rand.add((min(a, b), max(a, b)))
    rand_pairs = sorted(rand)

    if not same or not rand_pairs:
        return {
            "test": "go-no-go-2-separability",
            "cutoffs": {"pass_auc": pass_auc},
            "n_same": len(same),
            "n_random": len(rand_pairs),
            "verdict": "UNRESOLVED",
            "reason": "need at least one same-group and one random pair",
        }

    sigs = F.trace_signatures(texts)
    cos = F.tfidf_cosine(texts)
    pairs = [(a, b, 1) for a, b in same] + [(a, b, 0) for a, b in rand_pairs]
    mj = [F.minhash_jaccard(sigs[a], sigs[b]) for a, b, _ in pairs]
    tc = [float(cos[a, b]) for a, b, _ in pairs]
    labels = [lbl for _, _, lbl in pairs]
    auc_mh, auc_tf = F.auc(mj, labels), F.auc(tc, labels)
    verdict = "GO" if max(auc_mh, auc_tf) >= pass_auc else "NO-GO"
    return {
        "test": "go-no-go-2-separability",
        "cutoffs": {"pass_auc": pass_auc},
        "n_same": len(same),
        "n_random": len(rand_pairs),
        "auc_minhash_jaccard": round(auc_mh, 4),
        "auc_tfidf_cosine": round(auc_tf, 4),
        "verdict": verdict,
        "seed": seed,
    }


def main() -> None:
    import os

    from lab.convert import event_schema as es

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--traces", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--trace-groups", default=None,
                    help="JSON {trace_id: group}; default derives CTA session->actor map")
    ap.add_argument("--n-pairs", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    manifest = es.load_json(a.manifest)
    if a.trace_groups:
        groups = es.load_json(a.trace_groups)
    else:
        # CTA default: trace anchor is the session id; manifest carries
        # sessions_per_actor, so rebuild session->actor from splits if present.
        groups = {}
        try:
            per_actor = es.load_json(
                os.path.join(os.path.dirname(a.manifest), "splits.json")
            ).get("per_actor_time_forward", {})
            for actor, sp in per_actor.items():
                for s in sp["train"] + sp["val"] + sp["test"]:
                    groups[f"{actor}::{s}"] = actor
        except OSError:
            pass
        groups.update(_trace_groups(manifest))
    report = evaluate_separability(es.read_parquet(a.traces), groups, a.n_pairs, a.seed)
    print(json.dumps(report, indent=2))
    if a.out:
        es.dump_json(report, a.out)


if __name__ == "__main__":
    main()
