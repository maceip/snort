# Live ingest, query, and grouping architecture

All eight implementation gaps from the review are now wired into the service.
See [the API and recovery contracts](live-api.md) and the
[implementation plan](live-implementation-plan.md).

```text
[CLI readers / HTTP JSON or JSONL]
                 |
[Validate + normalize + preserve anchors/evidence]
                 |
[Source receipts / sequence allocation / retry conflict checks]
                 |
[Hash-chained JSONL WAL: flush + fsync]
                 |
[Live trace assembly -> candidate retrieval -> budgeted pair scoring]
                 |
[Overlapping groups: global active membership cap = 3]
                 |
[SQLite transaction: receipts, checkpoints, traces, groups, model, ledger]
                 |
[Atomic BLAKE3 ledger export -> successful acknowledgement]

QUERY (coordinated with ingest/seal)
  Default text: DuckDB UNION ALL over sealed Lance + Arrow wal_buffer
  Optional BM25: native Lance FTS + filtered WAL/unindexed substring hits
  Structured SQL: read-only snapshots of events and live grouping tables

PERSISTENCE / REVIEW
  Startup: recover orphan WAL -> replay missing projection receipts
  Group API: memberships, evidence, timelines, persisted analyst decisions
  Model API: supplied-label logistic/isotonic training and persisted parameters
  Ledger API: exported chain verified against committed head
```

The default scoring mode is an identified evidence baseline, not a claim of
real-world probability calibration. Supplied pair labels enable the existing
logistic/isotonic model. SQL GROUP BY and overlapping trace grouping are separate
capabilities. Lance sealing/indexing is explicit; it is not triggered merely by
WAL rotation. New WAL files are plain JSONL; legacy compressed WAL is readable.

The six-stage research/demo architecture in `plan.md` still includes attribution
and full attack reconstruction. Those are separate library/demo capabilities;
this service exposes the live ingest, grouping, review, and query paths above.
