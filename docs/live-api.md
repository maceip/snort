# Live ingest, grouping, and analytics

Start the persistent single-process service:

```bash
snort serve --data-dir ./snort_data --host 127.0.0.1 --port 8080
```

The dashboard includes event search, group inspection, SQL analytics, and visible
API errors. A successful ingest response means the new events have been fsynced
to WAL, processed into traces/groups, and committed to the local SQLite projection
and exported BLAKE3 ledger. Searches and writes use the same store lock.

## Endpoints

| Method | Path | Input / result |
| --- | --- | --- |
| POST | `/ingest`, `/api/ingest` | Event object, array, or JSONL; returns ingested/duplicate counts and scoring mode. |
| GET | `/api/search` | `q`, optional `filter`, `bm25`, `limit`; searches sealed Lance plus unsealed WAL. |
| POST / GET | `/api/query` | JSON `{ "sql": "SELECT ...", "limit": 1000 }`, or query parameters; read-only SQL results. |
| GET | `/api/traces` | Persisted trace summaries and current group IDs; optional `limit`. |
| GET | `/api/groups` | Groups, membership states, strengths, and evidence; optional `limit`. |
| GET | `/api/groups/{id}` | One group with its trace timeline and current scoring mode. |
| POST | `/api/groups/{id}/review` | `{ "trace_id": "...", "decision": "analyst-confirmed" }` or `analyst-rejected`; persisted and audited. |
| POST | `/api/model/train` | `{ "pairs": [{ "a": "trace-id", "b": "trace-id", "match": 1 }, ...] }`; requires both positive and negative labels. |
| GET | `/api/sources` | Durable per-source maximum committed sequence numbers. |
| GET | `/api/ledger/verify` | Verifies the exported chain against the committed ledger head. |
| POST | `/api/seal` | Rolls WAL, seals to Lance, and verifies/builds both native indexes. |
| GET | `/api/status` | Accurate event/store counts, source checkpoints, groups, and scoring mode. |

Invalid JSON, invalid records, malformed filters, and invalid SQL return structured
HTTP 400 errors. Identity conflicts return 409, missing resources return 404,
oversized request bodies return 413, and storage/internal failures return 500.
Validation rejects an entire invalid batch before writing. An I/O failure may
leave a durable prefix of a valid batch; retry resumes it without duplication.

## Event and retry contract

Required fields are `ts` (timezone-bearing ISO timestamp or epoch seconds),
`host`, and `action`. Supply `raw`, `subject`, `object`, and evidence such as
`session_id`, `root_pid`, `tokens`, `techniques`, `indicators`, and `entities`.
Anchor/evidence fields are preserved in the stored `attributes` JSON.

```json
{
  "ts": "2026-10-02T12:00:00Z",
  "host": "ws-2",
  "source_id": "agent-1",
  "source_seq": 42,
  "session_id": "shell-17",
  "subject": "process:17",
  "action": "exec",
  "raw": "powershell credential dump 10.0.0.1",
  "techniques": ["T1003"],
  "indicators": {"ip": ["10.0.0.1"]}
}
```

Prefer stable `source_id` and nonnegative `source_seq`. Reusing a sequence for
identical content is a duplicate; different content is a conflict. When sequence
numbers are absent, the service assigns them from durable source checkpoints and
deduplicates identical normalized content. An explicit `event_id` distinguishes
separate otherwise-identical events. An optional `Idempotency-Key` header binds
an entire batch to its content, including its size and ordering. Event IDs are
checked independently of that batch key: a new key cannot duplicate an existing
event ID or accept changed content under it. Existing receipt projections are
upgraded on startup, including event IDs from request-scoped receipts and legacy
WAL content fingerprints. Retries also recognize the fingerprint format used
before the newer template/tag/entropy enrichment; the original WAL and event
hashes are preserved.

New WAL segments are incremental plain JSONL, with flush/fsync per event. Legacy
compressed segments remain readable. Startup verifies and manifests orphan tails,
trims incomplete final records, and replays durable events missing from SQLite.
One process holds locks on both the data directory and the resolved WAL directory;
another writer cannot open either resource, even with a different data directory
or a symlink to the same WAL.
Use HTTP sealing/indexing while the server is running; standalone CLI seal/index
operations also take the writer lock.

Legacy sealed segments written before `flux_tags` was introduced remain readable.
Search and SQL snapshots project a zero tag mask without rewriting stored events
or segment hashes.

## Group scoring and review

The default mode is `evidence-baseline`: 45% MinHash similarity, 30% TF-IDF
cosine, 15% shared-indicator presence, and 10% technique overlap. It
is not a calibrated real-world probability. Candidate retrieval combines LSH,
indicators, and temporal shared-entity provenance, caps candidates at 50, and uses
a best-first comparison budget. Seeding requires score >= 0.8 and at least two
supporting evidence classes. Membership assignment requires strength >= 0.5.

Train with supplied positive/negative trace-pair labels to switch to the existing
logistic/isotonic model. Model parameters survive restart; the ledger records
training and scoring mode. Very small training sets use in-sample calibration,
so callers must supply representative labels before interpreting probabilities
as operationally calibrated. The service does not train on hidden demo labels.

A trace has at most three active memberships, including seeded memberships and
all subsequent assignments. Automatic memberships become `unsupported` when
current evidence falls below the assignment threshold; strength and evidence
are refreshed, the history remains inspectable, and their active slots are freed.
Previously supported memberships with scores between 0.5 and 0.8 become proposed.
Existing stores receive a one-time startup repair from their saved pair evidence;
the repair is recorded in the ledger and preserves analyst decisions.
Changed traces invalidate previous pair scores; pairs not rescored within the
current retrieval/budget cannot retain automatic support. Analyst confirmation
and rejection remain explicit decisions. Confirmation cannot exceed the active
cap, including reactivation of an unsupported membership. Groups are overlapping;
merge proposals do not perform automatic transitive closure.

## SQL and CLI

Read-only SQL operates on a consistent snapshot of `events`, `traces`,
`trace_events`, `groups`, `memberships`, `source_checkpoints`, and `decisions`.
`trace_events` joins event hashes to trace IDs. SQL has no external filesystem or
network access, accepts one SELECT statement, and caps output at 10,000 rows.
`events.ts` is a timezone-aware timestamp. Search filters and SQL interpret
date-only boundaries in UTC and compare equivalent timestamp offsets equally.
SQL timestamps are returned as ISO strings; decimals are strings to retain precision.

```sql
SELECT host, count(*) AS events FROM events GROUP BY host;

SELECT host, count(*) AS events FROM events
WHERE ts >= '2026-10-02' AND ts < '2026-10-03'
GROUP BY host;

SELECT m.group_id, e.host, count(*) AS events
FROM events e
JOIN trace_events t USING (event_hash)
JOIN memberships m USING (trace_id)
WHERE m.state NOT IN ('analyst-rejected', 'unsupported')
GROUP BY m.group_id, e.host;
```

```bash
snort ingest events.jsonl --server http://127.0.0.1:8080 --source-id sensor-1
snort query 'SELECT host, count(*) AS n FROM events GROUP BY host' --data-dir ./snort_data
snort groups --data-dir ./snort_data
snort traces --data-dir ./snort_data
```

Use `--server` to ingest into a running service. Without it, CLI ingestion opens
the local store exclusively; stop its server first. CLI ingestion uses batches
of 1,000 records and persistent source receipts. Retry
can reread the input without duplicating committed events. Its source namespace
defaults to the input's absolute path plus reader source; `--source-id` supplies
a stable namespace. CLI SQL opens a read-only SQLite snapshot, so it can inspect
a running server's store without taking its writer lock.

Default evidence search retains DuckDB's unified Lance/WAL scan. If the Lance
extension is unavailable, it uses an explicitly tagged Arrow scan fallback.
BM25 uses native indexed sealed segments and substring matches on WAL/unindexed
segments; every path applies the requested SQL filter. WAL/fallback scores are
fixed at 0.5; BM25 scores from different segments are not globally normalized.
Sealing/indexing remains an explicit operation.

## Verification

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m unittest discover -s third_party/dynahash/tests -t third_party/dynahash
.venv/bin/python scripts/verify_live_runtime.py
```

The separate HTTP proof verifies ingest, immediate search, real grouping, SQL,
review, supplied-label training, native BM25, errors, retries, checkpoints, and a
SIGKILL/restart with acknowledged events still in an open WAL. Its report is
written to `bench/results/live-runtime/report.json`.
