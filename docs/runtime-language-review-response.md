# Response: runtime language and ServiceTalk review

Scope: review of the sister team's assessment of `snort` (ServiceTalk/JVM adoption) and
their Netty-vs-Python comparison. All claims below were checked against the working tree
at this commit.

## Verdict

**Concur with the conclusion — no ServiceTalk, no JVM, no rewrite. Do not change the
runtime language.**

**Do not concur with the reasoning.** The review rests on four factual errors about this
repository, and it optimizes an axis (network I/O throughput) that is not where `snort`'s
risk lives. The recommendation is right; the justification would lead to the wrong work
plan next quarter.

Two items in the review are severe enough to be re-stated as findings rather than
corrections, because they invert the review's own premise:

1. Networking is not a "Version 2 addition." It is already shipped and it is the default
   entry point.
2. The ingest path is not "fully functional and verified by tests." Two tests fail, one of
   them on the live HTTP ingest path, and the failure exposes a durability bug.

---

## 1. Factual corrections

### 1.1 "Zero networking on the critical path" — false

`snort` with no arguments launches the HTTP server:

- `snort/cli.py:433` — `return _cmd_serve(parser.parse_args(["serve"]))`, i.e. bare `snort`
  starts the network ingest sink.
- `snort/server.py` (568 lines): `POST /ingest` and `/api/ingest`, `GET /api/search`,
  `POST /api/seal`, `GET /api/status`, `POST /api/demo`, and an embedded HTML dashboard
  (`server.py:421-565`).
- `snort/cli.py:370-375` — `serve` subcommand with `--host`, `--port`, `--open`.

The question being debated is therefore not "should we add networking later." It is
"the networking we already shipped is on the default path and has a correctness bug —
what do we do about it." That is a different decision with a different cost.

### 1.2 "Ingest into the BLAKE3 WAL is verified by tests" — partially false

`.venv/bin/python -m pytest -q` → **66 passed, 2 failed.**

| Test | Status | Cause |
|---|---|---|
| `tests/test_server.py:55` | FAIL | Search over the WAL tail immediately after HTTP ingest returns `0` hits, expected `1`. |
| `tests/test_gonogo.py:112` | FAIL | Test shells out to hardcoded `"python3"` instead of `sys.executable`; system interpreter lacks `pandas`. |

The first failure is the substantive one. Root cause:

- `snort/ingest/wal.py:115-133` — `WalWriter.append()` writes into a zstd stream writer and
  returns. No `flush`, no `fsync`.
- `snort/ingest/wal.py:140-145` — `flush()` + `os.fsync()` occur **only** in `roll()`.

Consequence: `POST /ingest` returns HTTP 200 for records that are neither visible to a
subsequent `/api/search` nor durable across a crash. `snort/ingest/wal.py:13` still asserts
"writers flush and fsync before returning," which is stale; `docs/architecture.md:53-59`
documents the gap correctly. The module docstring and the architecture doc disagree, and
the code follows the architecture doc.

This is a P0 correctness defect on a shipped, default-on path. It is not a throughput
problem, and it would reproduce identically in Java.

### 1.3 "Parquet segments" — wrong format, and it matters

`snort` uses **Lance**, not Parquet: `pylance` in `pyproject.toml`, `lance.write_dataset()`
at `snort/store/seal.py:88`, `seg-*.lance` datasets, native `INVERTED` (BM25 FTS) and
`BTREE` indexes.

This is not pedantry. Lance is Rust-backed, ships its own full-text and vector index
formats, and its scan path is where CPU time actually goes on the read side. Framing the
store as "batch Parquet/DuckDB" misidentifies both the read path and the tuning surface.
(`snort/cli.py:312` and `:384` still print "seal WAL segments to Parquet" — stale help text
that should be corrected.)

### 1.4 "20k–50k events/s (batch Parquet/DuckDB)" — unmeasured

There is no throughput benchmark anywhere in the repository. `bench/` contains only the
synthetic demo (`metrics.md`, `summary.json`, `ledger.jsonl`). Neither the Python figure
(20k–50k) nor the Netty figure (200k+) is derived from this codebase.

The current implementation has obvious, language-independent serialization points that
would dominate any measurement long before the GIL does:

- `snort/server.py:35,41-49` — a single process-wide `threading.Lock` held across the
  entire ingest loop, including per-record `normalize_event` + BLAKE3 + `json.dumps`.
- `snort/server.py:10,548` — stdlib `ThreadingHTTPServer`: thread-per-connection, no
  connection pooling.
- `snort/store/search.py:102` — a `UNION ALL` view is reconstructed per query.

Recommendation: measure before arguing about runtimes. A one-file ingest benchmark that
reports events/s is a prerequisite for any runtime decision, and it costs an afternoon.

---

## 2. Where the review is correct

- **Upstream research code is Python.** Unveiling-CTAs, PIDSMaker/ORTHRUS, DynaHash,
  Tracegram/ThreatTrace are all Python or Python/PyTorch. Re-implementing token
  normalizers, MinHash/LSH formulas, and DAG traversals in Java is weeks of work with no
  scientific payoff.
- **Reuse is real but not free.** `third_party/dynahash/` is vendored *with a fix suite*
  (`third_party/dynahash/tests/test_dynahash_fixes.py`, plus `original/` for comparison).
  This slightly overstates the review's "direct drop-in" claim while reinforcing its
  conclusion: reuse happens in Python, and it still requires work.
- **ServiceTalk specifically is the wrong JVM choice even if we went JVM.** Its
  differentiating value is *smart client* behavior — client-side load balancing, service
  discovery, outlier detection. `snort` is a sink, not a mesh client. As the review's own
  closing section notes, the raw-Netty or off-the-shelf-collector route would be the
  choice. ServiceTalk solves a problem `snort` does not have.
- **The storage boundary is the right isolation.** Keeping the WAL/Lance segment boundary
  as the contract between collector and brain is correct and should be preserved
  deliberately.

---

## 3. The argument the review missed: zero-copy Arrow, not threads

The review's strongest pro-Java claim is "no GIL, zero-copy buffers, true multi-core."
For `snort` specifically, the JVM is the *worst* place to buy that:

- `snort` already lives on Arrow: `pyarrow`, Lance, DuckDB. Its columnar memory format is
  the interchange layer.
- **Rust can hand Arrow arrays to Python with zero copy** (`arrow-rs` + PyO3, via the Arrow
  C data interface). The hot loops — MinHash, banding, TF-IDF, canonical hashing — can move
  to native code incrementally, one function at a time, with Stages 2-6 unchanged in Python.
- **Java cannot.** JVM-to-CPython Arrow handoff requires a copy or a JNI/Py4J bridge, i.e.
  exactly the IPC cost the review cites as disqualifying — just relocated.

So if a new runtime language ever becomes necessary, the answer is **Rust extension
modules, not a Java rewrite.** It is incremental, it preserves `scikit-learn`/`duckdb`/
`lance`, and it keeps the same buffer format. Java would forfeit all three and force
Stages 2-6 to be rewritten.

## 4. What is actually wrong — ranked

The sweeping changes worth making are not language changes.

### P0a — Fix the ingest durability and visibility contract

Decide explicitly and implement:

1. ACK semantics: ACK-after-append (current, lossy) vs ACK-after-fsync (durable, slower) vs
   ACK-after-group-commit (batched). Group commit is the usual answer.
2. A batch append API so the flush/fsync cost is amortized per batch, not per event.
3. Reconcile `snort/ingest/wal.py:13` with actual behavior.
4. Fix `tests/test_server.py:55`, or fix the code it is correctly catching.

Estimate: ~50 lines plus tests. This is the single highest-value change in the repo and it
is smaller than any runtime discussion.

### P0b — Validate on real data before touching the runtime

`bench/results/demo/summary.json`: 255 decisions — **130 `candidates`, 125 `unresolved`,
0 `attributed`.** `neighbour_recall` 0.5076, `link_yield` 0.9575, pair P/R 1.0/1.0.

`bench/results/demo/metrics.md` already states the fixtures are synthetic with no temporal
drift and that absolute numbers are smoke-test level. The ablation deltas are the
diagnostic signal, and they are unambiguous:

| Ablation | Effect |
|---|---|
| Remove LSH (indicators only) | recall 0.476 → 0.4735 (~0.003) |
| Cosine threshold instead of pair model | precision 1.0 → 1.0, recall 1.0 → 0.999 |
| FIFO instead of best-first | link yield 0.9535 → **0.7075** |

Interpretation: on current fixtures, LSH retrieval and the calibrated pair model carry
almost no measurable load; only scheduling moves a metric. The system's differentiating
machinery is unvalidated, not merely unoptimized.

Converters already exist (`lab/convert/e3_cadets.py`, `lab/convert/cta.py`). Running
E3-CADETS and the CTA corpus through the go/no-go gates burns down the real risk.
A runtime rewrite burns calendar time on a risk that has not been shown to exist.

### P1 — Throughput work, gated on measurement

In order, all language-neutral:

1. Remove the process-wide lock in `SnortStoreManager.ingest_records`; move to a bounded
   queue with a single WAL writer thread.
2. Batch normalize + hash instead of per-record.
3. Replace `ThreadingHTTPServer` for the ingest endpoint only (keep the dashboard).
4. Cache the unified query view instead of rebuilding `UNION ALL` per request
   (`snort/store/search.py:102`).
5. Note: `search_events` (`server.py:63`) runs outside the lock that `seal_and_index`
   holds. `docs/architecture.md:42-45` lists coordinated ingest/seal/query snapshots as
   MISSING, and there is no concurrency test in the suite. Needs a test before it needs a
   fix.

### P2 — Process boundary, if and when the split is real

If the collector/brain split becomes the target architecture, make `snort serve` a separate
process writing to the shared WAL/segment directory. Use Vector or Fluent Bit as the edge
collector. Do not build a Netty gateway.

---

## 5. Reply to the sister team

> We agree with the conclusion and are not adopting ServiceTalk or the JVM.
>
> Two corrections to the premises, both of which change the work plan:
>
> 1. Networking is already shipped and is the default entry point (`snort` with no args
>    starts the HTTP sink). It is not a Version 2 question.
> 2. The ingest path has a live P0 defect: `POST /ingest` ACKs 200 before records are
>    flushed or fsynced, so acknowledged events are neither searchable nor crash-durable.
>    `tests/test_server.py` catches it and currently fails. The suite is 66 pass / 2 fail.
>
> On the throughput comparison: neither number is measured — there is no benchmark in the
> repo — and the current bottlenecks (a process-wide ingest lock, per-record hashing,
> thread-per-connection HTTP, per-query view rebuild) are language-independent and would
> reproduce in Java.
>
> On "new runtime language if necessary": if that day comes, it is Rust + PyO3 + Arrow, not
> the JVM. Rust can hand zero-copy Arrow buffers to CPython, so the hot loops move
> incrementally and Stages 2-6 stay in Python; Java cannot share Arrow buffers with pyarrow
> without a copy, which is the IPC cost the review correctly rejects, just relocated.
>
> Our next cycle goes to the P0s: the ingest durability contract, and real-data validation
> on E3-CADETS and the CTA corpus. On the current fixtures the pipeline emits 0 attributions
> out of 255 decisions, and removing LSH or the pair model changes recall by ~0.003. Until
> that changes on real data, runtime throughput is not the binding constraint.
