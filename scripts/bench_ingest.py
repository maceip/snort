"""Measure ingest, seal, and search throughput for the live snort store.

Run with .venv/bin/python scripts/bench_ingest.py. The store is temporary; only the
report is retained under bench/results/throughput/.

Purpose: every claim about events/s in this repository should come from this script
rather than from an estimate. It reports the durable-append path (the number that
matters, because an ingest acknowledgement now implies fsync) separately from sealed
search, so ingest and query costs are not conflated.
"""

import argparse
import json
import statistics
import time
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = ROOT / "bench" / "results" / "throughput"

TEMPLATE = (
    "powershell -enc {n} invoke-mimikatz dump credentials host=ws-{h} user=svc-{n}"
)


def _events(count, offset=0):
    return [
        {
            "ts": f"2024-01-01T{(offset + i) // 3600 % 24:02d}:{(offset + i) // 60 % 60:02d}:{(offset + i) % 60:02d}Z",
            "host": f"ws-{i % 8}",
            "action": "exec",
            "raw": TEMPLATE.format(n=offset + i, h=i % 8),
        }
        for i in range(count)
    ]


def _ingest_run(events, batch_size):
    from snort.server import SnortStoreManager

    with TemporaryDirectory() as tmp:
        with SnortStoreManager(Path(tmp) / "store") as store:
            batches = [
                events[i : i + batch_size]
                for i in range(0, len(events), batch_size)
            ]
            start = time.perf_counter()
            for batch in batches:
                store.ingest(batch, source="bench:throughput")
            elapsed = time.perf_counter() - start
            wal_search = _timed(lambda: store.search_events("powershell", limit=10))
            seal = _timed(lambda: store.seal_and_index())
            sealed_search = _timed(
                lambda: store.search_events("powershell", limit=10)
            )
            bm25_search = _timed(
                lambda: store.search_events("powershell", limit=10, bm25=True)
            )
            store.close()
    n = len(events)
    return {
        "batch_size": batch_size,
        "batches": len(batches),
        "events": n,
        "ingest_seconds": round(elapsed, 4),
        "ingest_events_per_second": round(n / elapsed, 1) if elapsed else None,
        "ingest_ms_per_event": round(elapsed * 1000 / n, 3) if n else None,
        "wal_search_ms": round(wal_search * 1000, 2),
        "seal_ms": round(seal * 1000, 2),
        "sealed_search_ms": round(sealed_search * 1000, 2),
        "sealed_bm25_search_ms": round(bm25_search * 1000, 2),
    }


def _timed(fn, repeats=3):
    """Median wall time in seconds over a few repeats."""
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=2000, help="events per run")
    parser.add_argument(
        "--batch-sizes",
        type=int,
        nargs="+",
        default=[1, 100, 1000],
        help="events per ingest call",
    )
    args = parser.parse_args(argv)

    events = _events(args.events)
    runs = [_ingest_run(events, size) for size in args.batch_sizes]

    # A single-event measurement is dominated by fsync, so report it as the durable
    # floor rather than as a representative throughput figure.
    best = max(r["ingest_events_per_second"] for r in runs)
    report = {
        "events_per_run": args.events,
        "runs": runs,
        "best_ingest_events_per_second": best,
    }

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    out_json = REPORT_DIR / "report.json"
    out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = [
        "# snort ingest throughput",
        "",
        f"Events per run: {args.events}. Durable append (fsync before acknowledgement).",
        "Search timings are the median of 3 calls.",
        "",
        "| batch size | batches | events/s | ms/event | WAL search ms | seal ms | sealed search ms | BM25 ms |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in runs:
        lines.append(
            "| {batch_size} | {batches} | {ingest_events_per_second} | {ingest_ms_per_event} "
            "| {wal_search_ms} | {seal_ms} | {sealed_search_ms} | {sealed_bm25_search_ms} |".format(
                **r
            )
        )
    lines += [
        "",
        f"Best observed ingest: **{best} events/s**.",
        "",
        "Caveat: single-process, local filesystem, synthetic events. The batch-size-1 row",
        "is the durable floor (one fsync per event), not a target.",
    ]
    out_md = REPORT_DIR / "report.md"
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("\n".join(lines))
    print(f"\nwrote {out_json}")
    print(f"wrote {out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
