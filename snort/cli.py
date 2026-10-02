"""snort command line: ingest, seal, index, search, verify, demo (plan section 0).

Stage commands (ingest/seal/index/search) move raw telemetry to searchable
sealed segments. ``verify`` recomputes the WAL + sealed hash chains.
``demo`` runs the end-to-end v1 demonstration (ingest -> represent ->
retrieve -> score -> group -> attribute) and writes the metrics report.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _cmd_ingest(args: argparse.Namespace) -> int:
    from snort.ingest.events import normalize_event
    from snort.ingest.readers import iter_cta_json, iter_e3_jsonl, iter_jsonl
    from snort.ingest.wal import WalWriter

    readers = {"cta": iter_cta_json, "e3": iter_e3_jsonl, "jsonl": iter_jsonl}
    if args.format not in readers:
        print(f"unknown format {args.format!r}; choose from {sorted(readers)}", file=sys.stderr)
        return 2
    count = 0
    with WalWriter(args.wal_dir, max_bytes=args.max_bytes) as wal:
        for raw in readers[args.format](args.input):
            wal.append(normalize_event(raw))
            count += 1
        wal.roll()
    print(json.dumps({"ingested": count, "wal_dir": str(args.wal_dir)}))
    return 0


def _cmd_seal(args: argparse.Namespace) -> int:
    from snort.store.seal import seal_segments

    entries = seal_segments(args.wal_dir, args.sealed_dir)
    print(json.dumps({"sealed": [e["name"] for e in entries], "count": sum(e["count"] for e in entries)}))
    return 0


def _cmd_index(args: argparse.Namespace) -> int:
    from snort.store.index import build_index

    entries = build_index(args.sealed_dir, args.index_dir, args.work_dir, backend=args.backend)
    print(json.dumps({"indexed": [e["segment"] for e in entries], "backend": args.backend}))
    return 0


def _cmd_search(args: argparse.Namespace) -> int:
    from snort.store.search import search

    matches = search(args.query, args.sealed_dir, args.index_dir, args.wal_dir, limit=args.limit)
    if args.json:
        print(json.dumps(matches, indent=2))
    else:
        for match in matches:
            print(f"{match['_segment']}:{match['_row']} [{match['_source']}] {match['raw'][:200]}")
        print(f"{len(matches)} match(es)", file=sys.stderr)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    from snort.ledger.chain import verify_store

    report = verify_store(args.wal_dir, args.sealed_dir)
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


def _cmd_demo_ingest(args: argparse.Namespace) -> int:
    """Tiny ingest-level replay: ingest, seal, index, search, verify."""
    import tempfile

    from snort.ingest.events import normalize_event
    from snort.ingest.wal import WalWriter
    from snort.ledger.chain import verify_store
    from snort.store.index import build_index
    from snort.store.search import search
    from snort.store.seal import seal_segments

    base = Path(tempfile.mkdtemp(prefix="snort-demo-")) if not args.dir else Path(args.dir)
    wal_dir, sealed_dir, index_dir = base / "wal", base / "sealed", base / "index"
    rows = [
        ("2024-01-01T00:00:01+00:00", "web-1", "e3-cadets", "nginx: connection from 10.10.34.20:72349"),
        ("2024-01-01T00:00:02+00:00", "web-1", "e3-cadets", "nginx: connection from 10.10.34.22:50010"),
        ("2024-01-01T00:01:00+00:00", "ws-2", "cta", "powershell -enc SQBuAHYAbwBrAGUALQBMAG8AZwBnAGkAbgBnAA=="),
        ("2024-01-01T00:02:00+00:00", "web-1", "e3-cadets", "src: /10.10.34.22 sshd login failed"),
    ]
    with WalWriter(wal_dir, max_bytes=10**6) as wal:
        for i, (ts, host, source, raw) in enumerate(rows):
            wal.append(normalize_event(
                {"ts": ts, "host": host, "action": "log", "object": raw, "raw": raw,
                 "source_id": source, "source_seq": i}))
        wal.roll()
    sealed = seal_segments(wal_dir, sealed_dir)
    indexed = build_index(sealed_dir, index_dir)
    queries = ["10.10.34.20:72349", "src: /10.10.34.22", "powershell"]
    report = {"segments": len(sealed), "indexed": len(indexed), "searches": {}}
    for query in queries:
        found = search(query, sealed_dir, index_dir, wal_dir)
        report["searches"][query] = len(found)
    report["verify"] = verify_store(wal_dir, sealed_dir)["ok"]
    report["dirs"] = str(base)
    print(json.dumps(report, indent=2))
    return 0 if report["verify"] else 1


def _ledger_paths(out: str) -> dict[str, str]:
    return {
        "ledger": os.path.join(out, "ledger.jsonl"),
        "metrics": os.path.join(out, "metrics.md"),
        "summary": os.path.join(out, "summary.json"),
    }


def run_demo(out: str, seeds: int = 5, budget: int = 400) -> dict:
    """Run the end-to-end v1 demonstration and return its summary dict."""
    from snort import __version__
    from snort.attrib.fusion import ActorAttributor
    from snort.demo_data import make_cta_like, make_e3_like
    from snort.eval.report import _sample_pairs, run_ablations, run_condition
    from snort.grouping import ScoredLink, assign_memberships, seed_groups
    from snort.ledger import Ledger, canonical
    from snort.retrieve import RetrievalIndex
    from snort.schedule import budgeted_pairs
    from snort.score import PairFeaturizer, PairModel

    os.makedirs(out, exist_ok=True)
    paths = _ledger_paths(out)
    ledger = Ledger()

    # Ingest: chain raw segments for both corpora (one segment each).
    train, test, known, heldout = make_cta_like(seed=0)
    e3 = make_e3_like(seed=0)
    seg_cta = canonical([t.tid for t in train + test])
    seg_e3 = canonical([t.tid for t in e3])
    ledger.append_segment(seg_cta, {"source": "cta-sessions"})
    ledger.append_segment(seg_e3, {"source": "e3-cadets"})

    # Represent + retrieve + score + group on the demo seed.
    index = RetrievalIndex()
    for t in test:
        index.insert(t)
    featurizer = PairFeaturizer()
    featurizer.fit(train + test)
    ledger.append(
        "features",
        inputs=[t.tid for t in test],
        model={"tfidf": "1-2gram", "minhash": 128},
        params={"segment_seqs": [0, 1]},
        context={"n_traces": len(test)},
        output=[t.minhash[:4] for t in test[:2]],
    )
    tids = [t.tid for t in test]
    cand_map = {tid: index.query(index.traces[tid]) for tid in tids}
    ledger.append(
        "candidates",
        inputs=tids,
        model={"lsh": "banded-minhash-32x4", "cap": 50},
        params={"theta": 0.5},
        context={"index_epoch": 0, "scheduler_round": 0, "budget": budget},
        output={k: v[:5] for k, v in cand_map.items()},
    )
    pairs = budgeted_pairs(index, tids, cand_map, "best_first", budget)
    ledger.append(
        "schedule",
        inputs=tids,
        model={"scheduler": "best-first"},
        params={"budget": budget},
        context={"scheduler_round": 1},
        output=pairs[:10],
    )

    pos, neg = _sample_pairs(train, 0)
    X = [featurizer.evidence(a, b).vector() for a, b in pos + neg]
    y = [1] * len(pos) + [0] * len(neg)
    model = PairModel()
    model.fit(X, y)
    scored: list[ScoredLink] = []
    link_prob: dict[tuple[str, str], float] = {}
    for a_id, b_id in pairs:
        a, b = index.traces[a_id], index.traces[b_id]
        ev = featurizer.evidence(a, b)
        p = float(model.predict_proba([ev.vector()])[0])
        link_prob[(a_id, b_id)] = p
        scored.append(ScoredLink(a=a_id, b=b_id, proba=p, n_classes=ev.n_classes()))
    ledger.append(
        "links",
        inputs=pairs,
        model={"pair_model": "logistic-isotonic"},
        params={"tau_seed": 0.8},
        context={"verified_pairs": len(pairs)},
        output=[(s.a, s.b, round(s.proba, 3)) for s in scored[:10]],
    )
    groups = seed_groups(scored)
    memberships, unassigned = assign_memberships(tids, groups, link_prob)
    ledger.append(
        "groups",
        inputs=[(s.a, s.b) for s in scored],
        model={"grouping": "overlapping-tau0.5"},
        params={"tau_m": 0.5, "max_memberships": 3},
        context={"group_state_version": 1},
        output={"n_groups": len(groups), "n_unassigned": len(unassigned)},
    )

    # Attribute: every demo group gets candidates or unresolved.
    attr = ActorAttributor()
    attr.fit(
        [t.text() for t in train],
        [t.actor or "?" for t in train],
        [t.techniques for t in train],
    )
    by_tid = {t.tid: t for t in test}
    decisions = []
    for g in groups:
        member_texts = [by_tid[m].text() for m in g.members if m in by_tid]
        techs: set[str] = set()
        for m in g.members:
            if m in by_tid:
                techs |= by_tid[m].techniques
        res = attr.attribute_group(f"group-{g.gid}", member_texts, techs)
        decisions.append({"group": res.group_id, "decision": res.decision})
    ledger.append(
        "attribution",
        inputs=[g.gid for g in groups],
        model=attr.model_hash_ctx,
        params={"unknown_prior": 0.3, "candidate_threshold": 0.3},
        context={"group_state_version": 1},
        output=decisions,
    )

    ok, errors = ledger.verify()
    ledger.save(paths["ledger"])

    rows, metrics_md = run_ablations(seeds=seeds)
    with open(paths["metrics"], "w", encoding="utf-8") as fh:
        fh.write(metrics_md)
    demo_metrics = run_condition(train, test, known, heldout, e3, seed=0)
    summary = {
        "version": __version__,
        "verify_ok": ok,
        "verify_errors": errors,
        "n_traces": len(test),
        "n_e3": len(e3),
        "n_groups": len(groups),
        "n_unassigned": len(unassigned),
        "decisions": decisions,
        "demo_metrics": demo_metrics,
        "ledger": paths["ledger"],
        "metrics": paths["metrics"],
    }
    with open(paths["summary"], "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, sort_keys=True)
    summary["ablation_rows"] = rows
    return summary


def run_verify(ledger_path: str) -> tuple[bool, list[str]]:
    from snort.ledger import Ledger

    ledger = Ledger.load(ledger_path)
    return ledger.verify()


def _cmd_demo_v1(args: argparse.Namespace) -> int:
    from snort import __version__

    summary = run_demo(args.out, seeds=args.seeds, budget=args.budget)
    print(f"snort demo v{summary['version']}: "
          f"{summary['n_traces']} traces, {summary['n_groups']} groups, "
          f"{summary['n_unassigned']} unassigned")
    print(f"verify: {'OK' if summary['verify_ok'] else 'FAIL'}")
    for d in summary["decisions"][:10]:
        print(f"  {d['group']}: {d['decision']}")
    print(f"ledger: {summary['ledger']}")
    print(f"metrics: {summary['metrics']}")
    return 0 if summary["verify_ok"] else 1


def _cmd_verify_ledger(args: argparse.Namespace) -> int:
    ok, errors = run_verify(args.ledger)
    print("OK" if ok else "FAIL")
    for e in errors:
        print(f"  {e}")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="snort", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest", help="append reader output to the WAL")
    ingest.add_argument("input", help="input file (CTA JSON, E3 JSONL export, or generic JSONL)")
    ingest.add_argument("--format", default="jsonl", choices=["cta", "e3", "jsonl"])
    ingest.add_argument("--wal-dir", default="wal", help="WAL directory")
    ingest.add_argument("--max-bytes", type=int, default=256 * 1024 * 1024)
    ingest.set_defaults(func=_cmd_ingest)

    seal = sub.add_parser("seal", help="seal WAL segments to Parquet")
    seal.add_argument("--wal-dir", default="wal")
    seal.add_argument("--sealed-dir", default="sealed")
    seal.set_defaults(func=_cmd_seal)

    index = sub.add_parser("index", help="batch-index sealed segments")
    index.add_argument("--sealed-dir", default="sealed")
    index.add_argument("--index-dir", default="index")
    index.add_argument("--work-dir", default=None)
    index.add_argument("--backend", default="auto", choices=["auto", "builtin", "logcloud"])
    index.set_defaults(func=_cmd_index)

    search = sub.add_parser("search", help="split-and-verify evidence search")
    search.add_argument("query")
    search.add_argument("--sealed-dir", default="sealed")
    search.add_argument("--index-dir", default="index")
    search.add_argument("--wal-dir", default="wal")
    search.add_argument("--limit", type=int, default=1000)
    search.add_argument("--json", action="store_true")
    search.set_defaults(func=_cmd_search)

    verify = sub.add_parser("verify", help="recompute the WAL + sealed hash chains")
    verify.add_argument("--wal-dir", default="wal")
    verify.add_argument("--sealed-dir", default="sealed")
    verify.set_defaults(func=_cmd_verify)

    verify_ledger = sub.add_parser("verify-ledger", help="recompute a decision ledger hash chain")
    verify_ledger.add_argument("ledger", help="path to ledger.jsonl")
    verify_ledger.set_defaults(func=_cmd_verify_ledger)

    demo = sub.add_parser("demo", help="run the end-to-end v1 demonstration")
    demo.add_argument("--out", default="bench/results/demo", help="output directory")
    demo.add_argument("--seeds", type=int, default=5, help="ablation seeds")
    demo.add_argument("--budget", type=int, default=400, help="comparison budget")
    demo.set_defaults(func=_cmd_demo_v1)

    demo_ingest = sub.add_parser("demo-ingest", help="tiny ingest-level replay on synthetic data")
    demo_ingest.add_argument("--dir", default=None, help="store directory (default: temp dir)")
    demo_ingest.set_defaults(func=_cmd_demo_ingest)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
