# snort defect register

Scoped to defects in the `snort` implementation. No runtime-language discussion.

Entries **D1–D12** were found in a first pass at 12:53–13:08 and re-reviewed at 13:35,
after another agent committed `8302fb2` (plan) and `3fe84b5`
("feat: deliver all eight live ingest and grouping upgrades"). That delivery covered the
same ground: `docs/live-implementation-plan.md` lists the zero-hit WAL search and the
BM25 host-filter bypass in its own "initial evidence" section.

**D13** is new, found by the throughput benchmark added in this pass.

---

## Status

| ID | Severity | Defect | Status |
|---|---|---|---|
| D1 | C | Ingest ACKs before data is visible or durable | **Fixed** by `3fe84b5` |
| D2 | C | Silent partial ingest reported as full success | **Fixed** by `3fe84b5` |
| D3 | H | Filter spliced raw into SQL; invalid filter silently disables filtering | **Fixed** by `3fe84b5`; hardened in this pass |
| D4 | H | BM25 path drops the filter on the WAL tail; mixed score scales | **Fixed** by `3fe84b5` |
| D5 | H | "Indexed" does not mean an index was created | **Fixed** by `3fe84b5` |
| D6 | M | No resumable offsets; re-ingest duplicates | **Fixed** by `3fe84b5` |
| D7 | M | `test_gonogo.py` hardcodes `python3` | **Fixed** in this pass |
| D8 | M | Process-wide lock; seal/search uncoordinated | **Fixed** by `3fe84b5` |
| D9 | M | No throughput measurement anywhere in the repo | **Benchmark added** in this pass (`scripts/bench_ingest.py`) |
| D10 | M | Live ingest path and analytics pipeline not connected | **Fixed** by `3fe84b5` |
| D11 | M | Attribution engine never produced an attribution | **Open** — blocked on real corpora |
| D12 | L | Documentation drift | **Fixed** — CLI/README by `3fe84b5`; reader docstring in this pass |
| D13 | M | Per-ingest cost grows with total traces (quadratic single-event ingest) | **Mitigated** in this pass; residual remains |

Verification snapshot on 2026-10-02: **93 passed, 0 failed** (`.venv/bin/python -m pytest -q --basetemp=<fresh>`),
and `scripts/verify_live_runtime.py` reports `ok: true` across ingest, grouping, SQL,
BM25 filtering, idempotent retry, sequence conflict, read-only SQL rejection, checkpoint
recovery, and ledger verification across an abrupt `SIGKILL` restart.

> Sandbox note: `tmp_path` fixtures fail with `PermissionError: EEXIST` on
> `pytest-of-unknown` in this environment. Run pytest with `--basetemp=/tmp/<fresh-dir>`.

## Review fixes on 2026-10-03

- Lock both the data directory and resolved WAL directory before recovery.
- Check stable event IDs independently of request keys, including old receipts.
- Refresh automatic group support, retaining inactive history and analyst labels;
  repair stale saved memberships once on startup with a ledger record.
- Use consistent legacy receipt fingerprints and accept identical retries of
  events normalized at `6bad1a8`, without rewriting their acknowledged hashes.
- Time one complete seal/index operation and verify its event count.
- Label the APK `Snort Demo` (`com.snort.demo`), remove stub native code and
  generated padding, and state that the UI contains no analysis engine.

Validation: **28 tests passed** in the current reorganized suite, including 17
new regression cases. The live HTTP proof passed event-ID retries across request
keys and an abrupt SIGKILL/restart. The rebuilt APK passed signature verification,
installation, launch, and visual inspection on an Android emulator.

Commit preparation also preserved the existing event-enrichment, retrieval,
edge-scoring, trigram-helper, research-note, and subsystem-test changes. Inspection
found and fixed missing wheel packaging for the BK-tree, recursion and expired-key
growth in probe trees, and searches of legacy sealed datasets without `flux_tags`.
Optional queue weighting now honors its switch, dense retrieval uses trace duration,
and the entropy fixture is deterministic. Research diagrams distinguish proposed
wiring from live service behavior.

Final local validation: **34 pytest cases and 23 DynaHash regressions passed**;
HTTP crash/restart, the full CLI demo and ledger verification, blob ingest/search,
and ingest/search/ledger checks from an isolated wheel all passed.

---

## D1 — **[C]** Ingest acknowledged before data was visible or durable — FIXED

Original reproduction: after `append()`, `0` bytes on disk and `0` records readable;
after `roll()`, `1`. Cause: `wal.py` wrote into the zstd stream with `flush()`/`fsync()`
only in `roll()`.

Re-verified at 13:35: `1` record and `564` bytes readable immediately after `append()`.
The HTTP acknowledgement now implies fsync.

## D2 — **[C]** Silent partial ingest reported as full success — FIXED

Original: 5 submitted, 3 rejected, HTTP `{"ok": true, "ingested": 2}`, errors to stderr only.

Now: an invalid record raises before any write; the batch is atomic; `ingest()` returns
`ingested`, `duplicates`, `event_hashes`, and `scoring_mode`; the handler maps failures to
400/409/500. `Idempotency-Key` is honored via `request_receipts`.

## D3 — **[H]** Filter handling — FIXED, hardened in this pass

`_filter_rows` now pre-validates every filter through `duckdb.extract_statements`
(single `SELECT`, `enable_external_access=False`) and raises `RequestError` instead of
falling back to an unfiltered scan.

Verified at 13:35:

| filter | result |
|---|---|
| `host = 'ws-2'` | 1 hit |
| `host = 'nope'` | 0 hits |
| `ts >= TIMESTAMP '2024-01-01'` | 1 hit |
| `host ==` | `RequestError: invalid filter` |
| `1=1; SELECT 2` | `RequestError` (multi-statement) |
| `host IN (SELECT * FROM read_csv('/etc/passwd'))` | `RequestError` (external access) |

**Residual fixed in this pass:** a filter referencing the `events` table passed
pre-validation (where `events` is registered) but failed in the unified query with an
uncaught `duckdb.CatalogException`, surfacing as a 500 leaking DuckDB internals. The
unified query now exposes the union as an `events` CTE and wraps execution in
`except duckdb.Error -> RequestError`, so every filter failure is a clean, consistent 400.
Remaining minor gap: `events.host = 'x'` still fails to bind (fails loudly, not silently).

## D4 — **[H]** BM25 path dropped the filter on the WAL tail — FIXED

BM25 results now pass through the same `_filter_rows` predicate as live and fallback
results, and each hit reports `_search_mode`. Verified: `--bm25 --filter "host = 'ws-2'"`
returns only `ws-2`.

## D5 — **[H]** "Indexed" did not mean an index existed — FIXED

`build_lance_index` no longer swallows failures; it raises `RuntimeError` unless both
`event_hash_idx` and `raw_idx` exist, and re-verifies already-indexed segments on
subsequent runs.

## D6 — **[M]** No resumable offsets; re-ingest duplicated — FIXED

`source_checkpoints` plus content/sequence identity receipts. Verified: two identical
ingests → first `ingested 1 / duplicates 0`, second `ingested 0 / duplicates 1`, and the
checkpoint survives.

## D7 — **[M]** `test_gonogo.py` hardcoded `python3` — FIXED in this pass

`tests/test_gonogo.py` now uses `sys.executable`. The subprocess resolves to the venv
interpreter, which has `pandas`; the system interpreter does not. This was the last
failing test.

## D8 — **[M]** Locking and coordination — FIXED

`search_events`, `traces`, `groups`, `query`, and `review` all take the store lock;
a directory file lock guards multi-process access; ingest/seal/query are serialized.

## D9 — **[M]** No throughput measurement — BENCHMARK ADDED

`scripts/bench_ingest.py` measures durable ingest (events/s, ms/event), WAL search,
seal, sealed search, and BM25 search across batch sizes, and writes
`bench/results/throughput/report.{json,md}`.

Historical measurements on this machine, synthetic events, local filesystem:

| batch size | events | events/s | ms/event | WAL search ms | seal ms | sealed search ms | BM25 ms |
|---|---|---|---|---|---|---|---|
| 100 | 1500 | 174.2 | 5.74 | 16.1 | 13.4 | 74.9 | 29.9 |
| 500 | 1500 | 411.8 | 2.43 | 17.3 | 12.6 | 67.5 | 29.0 |

**Sealing correction (2026-10-03):** the historical `seal ms` values above are
invalid: the median covered one full seal and two empty operations. The benchmark
now times one complete seal/index operation, reports `seal_events`, and rejects
runs that do not seal every input event. A fresh 200-event run with batch sizes
1, 50, and 200 sealed 200 events in each run.

Context: the JVM-vs-Python review assumed 20k–50k events/s for `snort`. Measured durable
ingest is two orders of magnitude below that. Any future runtime or performance decision
should start from these numbers, not from estimates.

## D10 — **[M]** Live path and analytics not connected — FIXED

Ingest now feeds the assembler, candidate retrieval, scoring, and overlapping grouping;
`/api/traces`, `/api/groups`, `/api/groups/<id>`, review, and read-only SQL are exposed.
`verify_live_runtime.py` produces 3 groups from 4 HTTP-ingested events.

## D11 — **[M]** Attribution never produced an attribution — OPEN, blocked

`bench/results/demo/summary.json` still reports 255 decisions: 130 `candidates`,
125 `unresolved`, **0 attributed**, on synthetic fixtures with no temporal drift.
Ablations still show only the scheduler moving a metric.

This cannot be closed from this repository: no E3-CADETS or CTA corpus is present locally
(only the `lab/convert/e3_cadets.py` and `lab/convert/cta.py` converters). Next step is to
obtain the corpora and run the go/no-go gates against them. Until real data moves
`neighbour_recall` and produces non-zero attributions, the differentiating stages remain
unvalidated.

## D12 — **[L]** Documentation drift — FIXED

CLI and README "Parquet" references corrected to Lance; the false `wal.py` fsync claim
corrected. In this pass, `snort/ingest/readers.py` was corrected: the module docstring
claimed the per-invocation sequence counter makes "file tails resume from committed
offsets," which it does not — ordering is per-run, and re-ingestion safety comes from
runtime identity receipts and checkpoints.

---

## D13 — **[M]** Per-ingest cost grew with total traces — MITIGATED

Found by the new benchmark. Single-event ingest throughput fell as the store grew:

| events ingested | before: ms/event | after: ms/event |
|---|---|---|
| 100 | 47.4 | 12.6 |
| 200 | 74.0 | 12.5 |
| 400 | 128.7 | 13.7 |
| 800 | — | 14.6 |

Per-event cost grew linearly with store size → quadratic total. This matters because
`POST /ingest` with one event per request is the common client pattern.

Profile of a 200-event run: `apply()` → `_rebuild_indexes()` accounted for **26.5 s of
30.7 s (86%)**, dominated by `minhash_signature` → `_perm_hash` (**33.9 M calls**),
because every ingest call rebuilt retrieval `Trace` objects for *all* traces, and
`Trace.__post_init__` recomputes shingles and the MinHash signature from scratch.

Fix: `_matching_trace` now caches one `Trace` per trace id, keyed on the exact inputs
(`tokens`, `techniques`, `indicators`, `entities`, `start_ts`, `end_ts`), and rebuilds
only when those inputs change. Because shingles, signature, and token counts are pure
functions of those inputs, the result is identical — `verify_live_runtime.py` returns the
same ledger head, group count, and check list before and after.

Result: per-event cost is now flat in store size (12.6 → 14.6 ms/event from 100 to 800
events); ~9.4× faster at n=400. Suite is 93 passed / 0 failed.

**Residual:** `_rebuild_indexes` still clears and repopulates the LSH, indicator, and
provenance indexes over all traces on every `apply()`, and `_context()` recomputes IDF
per grouping decision. Those are O(traces) per ingest and will dominate at larger scales.
The correct fix is incremental index updates and a cached IDF invalidated on change —
a larger change to freshly delivered code, deferred rather than rushed here.
