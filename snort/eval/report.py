"""Metrics report with the three v1 ablations (plan section 0.6).

Ablations (one stage removed at a time, end-to-end change reported):
- no LSH (indicators only);
- FIFO instead of best-first ordering;
- cosine threshold instead of the pair model.
"""

from __future__ import annotations

import random

from snort.attrib.fusion import ActorAttributor
from snort.demo_data import make_cta_like, make_e3_like
from snort.features import Trace
from snort.grouping import assign_memberships, seed_groups
from snort.grouping import ScoredLink
from snort.retrieve import RetrievalIndex
from snort.schedule import budgeted_pairs
from snort.score import CosineBaseline, PairFeaturizer, PairModel

BUDGET = 400


def _sample_pairs(traces: list[Trace], seed: int, n_pos=300, n_neg=300):
    rng = random.Random(seed)
    by_actor: dict[str, list[Trace]] = {}
    for t in traces:
        by_actor.setdefault(t.actor or "?", []).append(t)
    actors = [a for a in by_actor if a != "?"]
    pos, neg = [], []
    for _ in range(n_pos):
        a = rng.choice(actors)
        if len(by_actor[a]) < 2:
            continue
        x, y = rng.sample(by_actor[a], 2)
        pos.append((x, y))
    for _ in range(n_neg):
        a, b = rng.sample(actors, 2)
        neg.append((rng.choice(by_actor[a]), rng.choice(by_actor[b])))
    return pos, neg


def run_condition(
    train: list[Trace],
    test: list[Trace],
    known: list[str],
    heldout: list[str],
    e3: list[Trace],
    seed: int,
    retrieval_mode: str = "full",
    schedule_mode: str = "best_first",
    scorer_mode: str = "pair_model",
) -> dict:
    index = RetrievalIndex()
    for t in test:
        index.insert(t)
    featurizer = PairFeaturizer()
    featurizer.fit(train + test)

    pos, neg = _sample_pairs(train, seed)
    X = [featurizer.evidence(a, b).vector() for a, b in pos + neg]
    y = [1] * len(pos) + [0] * len(neg)
    pair_model: PairModel | None = None
    cos_base: CosineBaseline | None = None
    if scorer_mode == "pair_model":
        pair_model = PairModel()
        pair_model.fit(X, y)
    else:
        cos_base = CosineBaseline()
        cos_base.fit([featurizer.evidence(a, b).cosine for a, b in pos + neg], y)

    tids = [t.tid for t in test]
    cand_map = {tid: index.query(index.traces[tid], mode=retrieval_mode) for tid in tids}
    pairs = budgeted_pairs(index, tids, cand_map, schedule_mode, BUDGET)

    # Retrieval neighbour recall: same-actor indexed neighbours in candidate set.
    recs = []
    for t in test:
        if t.actor in heldout:
            continue
        truth = {o.tid for o in test if o.actor == t.actor and o.tid != t.tid}
        if not truth:
            continue
        got = set(cand_map[t.tid]) & truth
        recs.append(len(got) / len(truth))
    neighbour_recall = sum(recs) / len(recs) if recs else 0.0

    # Score budgeted pairs.
    link_prob: dict[tuple[str, str], float] = {}
    links: list[ScoredLink] = []
    n_true_scored = 0
    for a_id, b_id in pairs:
        a, b = index.traces[a_id], index.traces[b_id]
        ev = featurizer.evidence(a, b)
        if pair_model is not None:
            p = float(pair_model.predict_proba([ev.vector()])[0])
        else:
            assert cos_base is not None
            p = float(cos_base.predict_proba([ev.cosine])[0])
        link_prob[(a_id, b_id)] = p
        links.append(ScoredLink(a=a_id, b=b_id, proba=p, n_classes=ev.n_classes()))
        n_true_scored += a.actor is not None and a.actor == b.actor
    # Comparison efficiency: share of the fixed comparison budget spent on
    # same-actor pairs. This is what best-first scheduling is supposed to
    # maximise, and what the FIFO ablation removes.
    link_yield = n_true_scored / len(pairs) if pairs else 0.0

    # Grouping pairwise precision/recall on scored links (p >= 0.5 ~ link).
    tp = fp = fn = 0
    for link in links:
        same = index.traces[link.a].actor == index.traces[link.b].actor
        pred = link.proba >= 0.5
        if pred and same:
            tp += 1
        elif pred:
            fp += 1
        elif same:
            fn += 1
    pair_prec = tp / (tp + fp) if (tp + fp) else 0.0
    pair_rec = tp / (tp + fn) if (tp + fn) else 0.0

    groups = seed_groups(links)
    _, unassigned = assign_memberships(tids, groups, link_prob)

    # Attribution: fit on train (known actors only), test singletons + E3.
    attr = ActorAttributor()
    attr.fit(
        [t.text() for t in train],
        [t.actor or "?" for t in train],
        [t.techniques for t in train],
    )
    top1 = top3 = n_known_test = 0
    heldout_unresolved = 0
    n_heldout = 0
    for t in test:
        res = attr.attribute_group(t.tid, [t.text()], t.techniques)
        if t.actor in heldout:
            n_heldout += 1
            heldout_unresolved += res.decision == "unresolved"
        else:
            n_known_test += 1
            ranked = [a for a, _ in res.ranking]
            if ranked and ranked[0] == t.actor:
                top1 += 1
            if t.actor in ranked[:3]:
                top3 += 1
    e3_unresolved = 0
    for t in e3:
        res = attr.attribute_group(t.tid, [], t.techniques)
        e3_unresolved += res.decision == "unresolved"

    return {
        "neighbour_recall": round(neighbour_recall, 4),
        "link_yield": round(link_yield, 4),
        "pair_precision": round(pair_prec, 4),
        "pair_recall": round(pair_rec, 4),
        "n_groups": len(groups),
        "n_unassigned": len(unassigned),
        "attr_top1": round(top1 / n_known_test, 4) if n_known_test else 0.0,
        "attr_top3": round(top3 / n_known_test, 4) if n_known_test else 0.0,
        "heldout_unresolved": round(heldout_unresolved / n_heldout, 4) if n_heldout else 0.0,
        "e3_unresolved": round(e3_unresolved / len(e3), 4) if e3 else 0.0,
    }


CONDITIONS = [
    ("full pipeline", {}, {}),
    ("no LSH (indicators only)", {"retrieval_mode": "indicators_only"}, {}),
    ("FIFO instead of best-first", {"schedule_mode": "fifo"}, {}),
    ("cosine threshold instead of pair model", {"scorer_mode": "cosine"}, {}),
]


def run_ablations(seeds: int = 5) -> tuple[list[dict], str]:
    rows: list[dict] = []
    per_seed: dict[str, list[dict]] = {name: [] for name, _, _ in CONDITIONS}
    for seed in range(seeds):
        train, test, known, heldout = make_cta_like(seed=seed)
        e3 = make_e3_like(seed=seed)
        for name, kwargs, _ in CONDITIONS:
            m = run_condition(train, test, known, heldout, e3, seed, **kwargs)
            m["condition"] = name
            m["seed"] = seed
            per_seed[name].append(m)
    keys = [
        "neighbour_recall",
        "link_yield",
        "pair_precision",
        "pair_recall",
        "attr_top1",
        "attr_top3",
        "heldout_unresolved",
        "e3_unresolved",
    ]
    for name, _, _ in CONDITIONS:
        row: dict = {"condition": name}
        for k in keys:
            vals = [m[k] for m in per_seed[name]]
            row[k] = round(sum(vals) / len(vals), 4)
            row[k + "_min"] = round(min(vals), 4)
            row[k + "_max"] = round(max(vals), 4)
        rows.append(row)

    lines = [
        "# snort v1 metrics report",
        "",
        f"Seeds: {seeds}. Synthetic CTA-like (6 known + 2 held-out actors) and "
        "E3-like (labelless provenance) fixtures; time-forward split.",
        "",
        "| condition | neighbour recall | link yield | pair P / R | "
        "attr top-1 / top-3 | held-out unresolved | E3 unresolved |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['condition']} | {r['neighbour_recall']} "
            f"({r['neighbour_recall_min']}-{r['neighbour_recall_max']}) | "
            f"{r['link_yield']} "
            f"({r['link_yield_min']}-{r['link_yield_max']}) | "
            f"{r['pair_precision']} / {r['pair_recall']} | "
            f"{r['attr_top1']} / {r['attr_top3']} | "
            f"{r['heldout_unresolved']} | {r['e3_unresolved']} |"
        )
    lines += [
        "",
        "Ablations remove one stage at a time (plan section 7.4, v1 subset): "
        "no LSH, FIFO scheduling, cosine scoring. Attribution stays at "
        "candidates/unresolved: command-only input never reaches attributed, "
        "and held-out actors plus E3 groups must read unresolved.",
        "",
        "Caveat: fixtures are synthetic with no temporal drift, so absolute "
        "numbers are smoke-test levels. Real baselines are measured on "
        "E3-CADETS and the CTA corpus in weeks 7-8; only the ablation "
        "deltas here exercise the pipeline logic.",
        "",
    ]
    return rows, "\n".join(lines)
