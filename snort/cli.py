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
import urllib.parse
from pathlib import Path


def _cmd_ingest(args: argparse.Namespace) -> int:
    from snort.ingest.readers import iter_cta_json, iter_e3_jsonl, iter_jsonl
    from snort.server import SnortStoreManager

    readers = {"cta": iter_cta_json, "e3": iter_e3_jsonl, "jsonl": iter_jsonl}
    base = (
        Path(args.data_dir)
        if args.data_dir
        else Path(args.wal_dir or "wal").resolve().parent
    )
    source = args.source_id or "file:" + str(Path(args.input).resolve())
    total, duplicates, batch = 0, 0, []
    from contextlib import nullcontext

    store_context = (
        nullcontext(None)
        if args.server
        else SnortStoreManager(base, wal_dir=args.wal_dir, max_bytes=args.max_bytes)
    )

    def commit(records, store):
        if store is not None:
            return store.ingest(records, source=source)
        import urllib.request

        req = urllib.request.Request(
            args.server.rstrip("/") + "/ingest",
            data=json.dumps(records).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=60) as response:
            return json.loads(response.read())

    with store_context as store:
        for raw in readers[args.format](args.input):
            raw = dict(
                raw, source_id=source + ":" + str(raw.get("source_id", "generic"))
            )
            batch.append(raw)
            if len(batch) == 1000:
                result = commit(batch, store)
                total += result["ingested"]
                duplicates += result["duplicates"]
                batch = []
        if batch:
            result = commit(batch, store)
            total += result["ingested"]
            duplicates += result["duplicates"]
        print(
            json.dumps(
                {
                    "ingested": total,
                    "duplicates": duplicates,
                    "store": args.server or str(store.data_dir),
                }
            )
        )
    return 0


def _cmd_query(args: argparse.Namespace) -> int:
    import sqlite3
    from snort.runtime import snapshot_tables
    from snort.store.search import query_tables

    db_path = Path(args.data_dir).resolve() / "runtime.sqlite3"
    with sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True) as db:
        db.execute("BEGIN")
        sql = (
            args.sql
            if args.subcommand == "query"
            else "SELECT * FROM " + args.subcommand
        )
        print(
            json.dumps(
                query_tables(sql, snapshot_tables(db), limit=args.limit), indent=2
            )
        )
    return 0


def _cmd_seal(args: argparse.Namespace) -> int:
    from snort.server import SnortStoreManager

    base = args.data_dir or Path(args.wal_dir).resolve().parent
    with SnortStoreManager(
        base, wal_dir=args.wal_dir, sealed_dir=args.sealed_dir
    ) as store:
        entries = store.seal()
    print(
        json.dumps(
            {
                "sealed": [e["name"] for e in entries],
                "count": sum(e["count"] for e in entries),
            }
        )
    )
    return 0


def _cmd_index(args: argparse.Namespace) -> int:
    from snort.store.index import build_index
    from snort.server import SnortStoreManager

    base = args.data_dir or Path(args.sealed_dir).resolve().parent
    with SnortStoreManager(
        base, sealed_dir=args.sealed_dir, index_dir=args.index_dir
    ) as store:
        entries = build_index(
            store.sealed_dir, store.index_dir, args.work_dir, backend=args.backend
        )
    print(json.dumps({"indexed": [e["segment"] for e in entries], "backend": "lance"}))
    return 0


def _cmd_search(args: argparse.Namespace) -> int:
    from snort.store.search import search

    matches = search(
        args.query,
        args.sealed_dir,
        args.index_dir,
        args.wal_dir,
        limit=args.limit,
        bm25=getattr(args, "bm25", False),
        filter_expr=getattr(args, "filter", None),
    )
    if args.json:
        print(json.dumps(matches, indent=2))
    else:
        for match in matches:
            score_str = f" (score={match['_score']:.3f})" if "_score" in match else ""
            print(
                f"{match['_segment']}:{match.get('_row', 0)} [{match['_source']}]{score_str} {match['raw'][:200]}"
            )
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

    base = (
        Path(tempfile.mkdtemp(prefix="snort-demo-")) if not args.dir else Path(args.dir)
    )
    wal_dir, sealed_dir, index_dir = base / "wal", base / "sealed", base / "index"
    rows = [
        (
            "2024-01-01T00:00:01+00:00",
            "web-1",
            "e3-cadets",
            "nginx: connection from 10.10.34.20:72349",
        ),
        (
            "2024-01-01T00:00:02+00:00",
            "web-1",
            "e3-cadets",
            "nginx: connection from 10.10.34.22:50010",
        ),
        (
            "2024-01-01T00:01:00+00:00",
            "ws-2",
            "cta",
            "powershell -enc SQBuAHYAbwBrAGUALQBMAG8AZwBnAGkAbgBnAA==",
        ),
        (
            "2024-01-01T00:02:00+00:00",
            "web-1",
            "e3-cadets",
            "src: /10.10.34.22 sshd login failed",
        ),
    ]
    with WalWriter(wal_dir, max_bytes=10**6) as wal:
        for i, (ts, host, source, raw) in enumerate(rows):
            wal.append(
                normalize_event(
                    {
                        "ts": ts,
                        "host": host,
                        "action": "log",
                        "object": raw,
                        "raw": raw,
                        "source_id": source,
                        "source_seq": i,
                    }
                )
            )
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
    summary = run_demo(args.out, seeds=args.seeds, budget=args.budget)
    print(
        f"snort demo v{summary['version']}: "
        f"{summary['n_traces']} traces, {summary['n_groups']} groups, "
        f"{summary['n_unassigned']} unassigned"
    )
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


def _cmd_serve(args: argparse.Namespace) -> int:
    from snort.server import run_server

    run_server(
        data_dir=args.data_dir,
        host=args.host,
        port=args.port,
        open_browser=getattr(args, "open", False),
    )
    return 0


def _fetch_telemetry(args: argparse.Namespace, path: str, store_fn):
    server = getattr(args, "server", None)
    if server:
        import urllib.request

        url = server.rstrip("/") + path
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            raise RuntimeError(f"failed to query snort server at {url}: {exc}") from exc
    from snort.server import SnortStoreManager

    data_dir = getattr(args, "data_dir", "./snort_data")
    with SnortStoreManager(data_dir) as store:
        return store_fn(store)


def _cmd_traces(args: argparse.Namespace) -> int:
    params = []
    if getattr(args, "service", None):
        params.append(f"service={urllib.parse.quote(args.service)}")
    if getattr(args, "status", None):
        params.append(f"status={urllib.parse.quote(args.status)}")
    if getattr(args, "limit", None):
        params.append(f"limit={args.limit}")
    qs = ("?" + "&".join(params)) if params else ""

    traces = _fetch_telemetry(
        args,
        f"/api/traces{qs}",
        lambda store: store.get_traces_summary(
            service=getattr(args, "service", None),
            status=getattr(args, "status", None),
            limit=getattr(args, "limit", 50),
        ),
    )
    if getattr(args, "json", False):
        print(json.dumps(traces, indent=2))
        return 0

    if not traces:
        print("no traces found.")
        return 0

    header = f"{'TRACE ID':<36} {'SERVICE':<18} {'ROOT OPERATION':<26} {'DURATION':<11} {'SPANS':<6} {'STATUS':<7} {'START TIME'}"
    print(header)
    print("-" * len(header))
    for t in traces:
        tid = str(t.get("trace_id", ""))
        svc = str(t.get("service", ""))[:17]
        op = str(t.get("root_operation", ""))[:25]
        dur = f"{t.get('duration_ms', 0):.2f}ms"
        spans = str(t.get("span_count", 1))
        st = str(t.get("status", "ok")).upper()
        ts = str(t.get("start_ts", ""))[:19]
        print(f"{tid:<36} {svc:<18} {op:<26} {dur:<11} {spans:<6} {st:<7} {ts}")
    return 0


def _cmd_spans(args: argparse.Namespace) -> int:
    target_id = getattr(args, "trace_id", None) or getattr(args, "span_id", None)
    if not target_id:
        return _cmd_traces(args)

    tree = _fetch_telemetry(
        args,
        f"/api/traces/{urllib.parse.quote(target_id)}",
        lambda store: store.get_trace_tree(target_id),
    )
    if tree and tree.get("spans"):
        if getattr(args, "json", False):
            print(json.dumps(tree, indent=2))
            return 0
        print(
            f"TRACE: {tree['trace_id']} (service: {tree['service']}, duration: {tree['duration_ms']:.2f}ms, spans: {tree['span_count']}, status: {tree['status'].upper()})"
        )
        for s in tree["spans"]:
            indent = "   " * s.get("depth", 0)
            prefix = "├─ " if s.get("depth", 0) > 0 else ""
            ai_info = ""
            if s.get("is_ai_call"):
                m = s.get("attributes", {}).get("ai_model", "")
                tok = s.get("attributes", {}).get("ai_total_tokens", 0)
                ai_info = f" [AI: {m} | {tok} tokens]"
            print(
                f"{indent}{prefix}[{s.get('offset_ms', 0):.2f}ms] {s.get('name')} ({s.get('service')}) {s.get('duration_ms', 0):.2f}ms [{s.get('status', 'ok').upper()}]{ai_info}"
            )
        return 0

    span = _fetch_telemetry(
        args,
        f"/api/spans/{urllib.parse.quote(target_id)}",
        lambda store: store.get_span(target_id),
    )
    if span:
        if getattr(args, "json", False):
            print(json.dumps(span, indent=2))
            return 0
        attrs = span.get("attributes", {})
        print(
            f"SPAN: {attrs.get('span_id', target_id)} ({attrs.get('service_name', span.get('source_id'))})"
        )
        print(f"Operation : {span.get('action')}")
        print(f"Duration  : {attrs.get('duration_ms', 0):.2f}ms")
        print(f"Status    : {attrs.get('status', 'ok').upper()}")
        print(f"Trace ID  : {attrs.get('trace_id') or span.get('session_id')}")
        print(f"Timestamp : {span.get('ts')}")
        print("\nAttributes:")
        for k, v in sorted(attrs.items()):
            if k not in ("events", "_snort_ingest"):
                print(f"  {k}: {v}")
        logs = span.get("correlated_logs", [])
        if logs:
            print(f"\nCorrelated Logs ({len(logs)}):")
            for l in logs:
                print(f"  [{l.get('ts')}] {l.get('raw')}")
        return 0

    print(f"Span or trace '{target_id}' not found.", file=sys.stderr)
    return 1


def _cmd_logs(args: argparse.Namespace) -> int:
    params = []
    if getattr(args, "service", None):
        params.append(f"service={urllib.parse.quote(args.service)}")
    if getattr(args, "trace_id", None):
        params.append(f"trace_id={urllib.parse.quote(args.trace_id)}")
    if getattr(args, "span_id", None):
        params.append(f"span_id={urllib.parse.quote(args.span_id)}")
    if getattr(args, "severity", None):
        params.append(f"severity={urllib.parse.quote(args.severity)}")
    if getattr(args, "limit", None):
        params.append(f"limit={args.limit}")
    qs = ("?" + "&".join(params)) if params else ""

    logs = _fetch_telemetry(
        args,
        f"/api/logs{qs}",
        lambda store: store.get_logs(
            service=getattr(args, "service", None),
            trace_id=getattr(args, "trace_id", None),
            span_id=getattr(args, "span_id", None),
            severity=getattr(args, "severity", None),
            limit=getattr(args, "limit", 50),
        ),
    )
    if getattr(args, "json", False):
        print(json.dumps(logs, indent=2))
        return 0

    if not logs:
        print("no logs found.")
        return 0

    for l in logs:
        ts = str(l.get("ts", ""))[:19]
        sev = str(l.get("severity", "INFO")).upper()
        svc = l.get("service", "unknown")
        msg = l.get("message", "")
        tid = l.get("trace_id", "")
        context = f" (trace: {tid[:12]}...)" if tid else ""
        print(f"[{ts}] [{sev:<5}] {svc}: {msg}{context}")
    return 0


def _cmd_services(args: argparse.Namespace) -> int:
    services = _fetch_telemetry(
        args,
        "/api/services",
        lambda store: store.get_services(),
    )
    if getattr(args, "json", False):
        print(json.dumps(services, indent=2))
        return 0

    if not services:
        print("no services found.")
        return 0

    header = f"{'SERVICE':<28} {'EVENTS':<10} {'ERRORS':<10} {'AI CALLS'}"
    print(header)
    print("-" * len(header))
    for s in services:
        print(
            f"{s.get('name', ''):<28} {s.get('events', 0):<10} {s.get('errors', 0):<10} {s.get('ai_calls', 0)}"
        )
    return 0


def _cmd_ai(args: argparse.Namespace) -> int:
    params = []
    if getattr(args, "service", None):
        params.append(f"service={urllib.parse.quote(args.service)}")
    if getattr(args, "model", None):
        params.append(f"model={urllib.parse.quote(args.model)}")
    if getattr(args, "limit", None):
        params.append(f"limit={args.limit}")
    qs = ("?" + "&".join(params)) if params else ""

    calls = _fetch_telemetry(
        args,
        f"/api/ai/calls{qs}",
        lambda store: store.get_ai_calls(
            limit=getattr(args, "limit", 20),
            service=getattr(args, "service", None),
            model=getattr(args, "model", None),
        ),
    )
    if getattr(args, "json", False):
        print(json.dumps(calls, indent=2))
        return 0

    if not calls:
        print("no AI calls found.")
        return 0

    header = f"{'TIMESTAMP':<19} {'SERVICE':<14} {'PROVIDER':<12} {'MODEL':<20} {'DURATION':<10} {'TOKENS (IN/OUT/TOT)':<22} {'PROMPT PREVIEW'}"
    print(header)
    print("-" * len(header))
    for c in calls:
        ts = str(c.get("timestamp", ""))[:19]
        svc = str(c.get("service", ""))[:13]
        prov = str(c.get("provider", ""))[:11]
        mdl = str(c.get("model", ""))[:19]
        dur = f"{c.get('duration_ms', 0):.1f}ms"
        tokens = f"{c.get('input_tokens',0)}/{c.get('output_tokens',0)} ({c.get('total_tokens',0)})"
        prompt = str(c.get("prompt_preview", ""))[:35]
        print(
            f"{ts:<19} {svc:<14} {prov:<12} {mdl:<20} {dur:<10} {tokens:<22} {prompt}"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="snort",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="subcommand")

    serve = sub.add_parser(
        "serve", help="launch embedded web dashboard and network ingest sink"
    )
    serve.add_argument(
        "--data-dir",
        default="./snort_data",
        help="storage directory (default: ./snort_data)",
    )
    serve.add_argument(
        "--host", default="127.0.0.1", help="listen host (default: 127.0.0.1)"
    )
    serve.add_argument(
        "--port", type=int, default=8080, help="listen port (default: 8080)"
    )
    serve.add_argument(
        "--open", action="store_true", help="open web dashboard in default browser"
    )
    serve.set_defaults(func=_cmd_serve)

    ingest = sub.add_parser("ingest", help="append reader output to the WAL")
    ingest.add_argument(
        "input", help="input file path (e.g. data_with_sclc.json or edges.jsonl)"
    )
    ingest.add_argument("--format", default="jsonl", choices=["cta", "e3", "jsonl"])
    ingest.add_argument("--wal-dir", default=None)
    ingest.add_argument("--data-dir", default=None)
    ingest.add_argument(
        "--source-id",
        default=None,
        help="stable source namespace for resumable ingestion",
    )
    ingest.add_argument(
        "--server", default=None, help="send batches to a running HTTP service"
    )
    ingest.add_argument("--max-bytes", type=int, default=256 * 1024 * 1024)
    ingest.set_defaults(func=_cmd_ingest)

    seal = sub.add_parser("seal", help="seal WAL segments to Lance")
    seal.add_argument("--wal-dir", default="wal")
    seal.add_argument("--sealed-dir", default="sealed")
    seal.add_argument("--data-dir", default=None)
    seal.set_defaults(func=_cmd_seal)

    index = sub.add_parser("index", help="batch-index sealed segments")
    index.add_argument("--sealed-dir", default="sealed")
    index.add_argument("--index-dir", default="index")
    index.add_argument("--work-dir", default=None)
    index.add_argument("--data-dir", default=None)
    index.add_argument(
        "--backend", default="auto", choices=["auto", "lance", "builtin"]
    )
    index.set_defaults(func=_cmd_index)

    search = sub.add_parser("search", help="split-and-verify evidence search")
    search.add_argument("query")
    search.add_argument("--sealed-dir", default="sealed")
    search.add_argument("--index-dir", default="index")
    search.add_argument("--wal-dir", default="wal")
    search.add_argument("--limit", type=int, default=1000)
    search.add_argument(
        "--bm25",
        action="store_true",
        help="rank results with Lance BM25 full-text scoring",
    )
    search.add_argument(
        "--filter",
        default=None,
        help="additional boolean filter expression (e.g. host = 'h1')",
    )
    search.add_argument("--json", action="store_true")
    search.set_defaults(func=_cmd_search)

    verify = sub.add_parser("verify", help="recompute the WAL + sealed hash chains")
    verify.add_argument("--wal-dir", default="wal")
    verify.add_argument("--sealed-dir", default="sealed")
    verify.set_defaults(func=_cmd_verify)

    verify_ledger = sub.add_parser(
        "verify-ledger", help="recompute a decision ledger hash chain"
    )
    verify_ledger.add_argument("ledger", help="path to ledger.jsonl")
    verify_ledger.set_defaults(func=_cmd_verify_ledger)

    demo = sub.add_parser("demo", help="run the end-to-end v1 demonstration")
    demo.add_argument("--out", default="bench/results/demo", help="output directory")
    demo.add_argument("--seeds", type=int, default=5, help="ablation seeds")
    demo.add_argument("--budget", type=int, default=400, help="comparison budget")
    demo.set_defaults(func=_cmd_demo_v1)

    demo_ingest = sub.add_parser(
        "demo-ingest", help="tiny ingest-level replay on synthetic data"
    )
    demo_ingest.add_argument(
        "--dir", default=None, help="store directory (default: temp dir)"
    )
    demo_ingest.set_defaults(func=_cmd_demo_ingest)

    query = sub.add_parser(
        "query", help="read-only SQL over events and live grouping tables"
    )
    query.add_argument("sql")
    query.add_argument("--data-dir", default="./snort_data")
    query.add_argument("--limit", type=int, default=1000)
    query.set_defaults(func=_cmd_query)
    groups = sub.add_parser("groups", help="inspect persisted threat groups")
    groups.add_argument("--data-dir", default="./snort_data")
    groups.add_argument("--limit", type=int, default=1000)
    groups.set_defaults(func=_cmd_query)

    traces = sub.add_parser("traces", help="inspect assembled traces (live or historical)")
    traces.add_argument("--service", default=None, help="filter by service name")
    traces.add_argument(
        "--status", default=None, choices=["ok", "error"], help="filter by status"
    )
    traces.add_argument(
        "--limit", type=int, default=50, help="max traces (default: 50)"
    )
    traces.add_argument(
        "--data-dir", default="./snort_data", help="storage directory"
    )
    traces.add_argument(
        "--server", default=None, help="query running snort server URL"
    )
    traces.add_argument("--json", action="store_true", help="output JSON array")
    traces.set_defaults(func=_cmd_traces)

    spans = sub.add_parser(
        "spans", help="inspect spans and render trace waterfall trees"
    )
    spans.add_argument(
        "span_id", nargs="?", default=None, help="span ID or trace ID to inspect"
    )
    spans.add_argument(
        "--trace-id", default=None, help="trace ID to render as an ASCII waterfall tree"
    )
    spans.add_argument("--limit", type=int, default=100, help="max spans limit")
    spans.add_argument(
        "--data-dir", default="./snort_data", help="storage directory"
    )
    spans.add_argument(
        "--server", default=None, help="query running snort server URL"
    )
    spans.add_argument("--json", action="store_true", help="output JSON")
    spans.set_defaults(func=_cmd_spans)

    logs = sub.add_parser(
        "logs", help="query and stream correlated telemetry logs"
    )
    logs.add_argument("--service", default=None, help="filter by service")
    logs.add_argument(
        "--trace-id", default=None, help="filter by correlated trace ID"
    )
    logs.add_argument(
        "--span-id", default=None, help="filter by correlated span ID"
    )
    logs.add_argument(
        "--severity", default=None, help="filter by severity (e.g. ERROR, WARN, INFO)"
    )
    logs.add_argument(
        "--limit", type=int, default=50, help="max logs limit (default: 50)"
    )
    logs.add_argument(
        "--data-dir", default="./snort_data", help="storage directory"
    )
    logs.add_argument(
        "--server", default=None, help="query running snort server URL"
    )
    logs.add_argument("--json", action="store_true", help="output JSON")
    logs.set_defaults(func=_cmd_logs)

    services = sub.add_parser(
        "services", help="list active services reporting telemetry"
    )
    services.add_argument(
        "--data-dir", default="./snort_data", help="storage directory"
    )
    services.add_argument(
        "--server", default=None, help="query running snort server URL"
    )
    services.add_argument("--json", action="store_true", help="output JSON")
    services.set_defaults(func=_cmd_services)

    ai = sub.add_parser(
        "ai", help="inspect detected AI SDK / LLM calls and token metrics"
    )
    ai.add_argument("--service", default=None, help="filter by service")
    ai.add_argument("--model", default=None, help="filter by model name")
    ai.add_argument(
        "--limit", type=int, default=20, help="max AI calls limit (default: 20)"
    )
    ai.add_argument(
        "--data-dir", default="./snort_data", help="storage directory"
    )
    ai.add_argument(
        "--server", default=None, help="query running snort server URL"
    )
    ai.add_argument("--json", action="store_true", help="output JSON")
    ai.set_defaults(func=_cmd_ai)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    if argv is None and len(sys.argv) == 1:
        # Default to launching plug-and-play web server and ingest sink
        return _cmd_serve(parser.parse_args(["serve"]))
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except Exception as exc:
        print(
            json.dumps({"ok": False, "error": type(exc).__name__, "message": str(exc)}),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
