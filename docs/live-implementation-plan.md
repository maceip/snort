# Live ingest and grouping implementation plan

Requested scope: implement and commit all eight gaps identified in the current
ingest/query/grouping review. Preserve existing checkout changes and the existing
single-process Lance/DuckDB architecture. Do not merge unrelated review documents.

## Delivery contract

An HTTP ingest acknowledgement must mean the events are durable, immediately
searchable, processed into traces, and reflected in persisted grouping state.
Restart must preserve events, memberships, analyst decisions, source checkpoints,
and the verifiable decision ledger. Retrying an event must not duplicate it.

| Gap | Implementation | Required proof |
| --- | --- | --- |
| 1. Live pipeline | Preserve anchor/evidence metadata during normalization; adapt stored events to assembler and matching Trace types; run candidate retrieval, bounded best-first scoring, and overlapping grouping on committed events. | Real HTTP input produces traces and supported groups without using the synthetic demo. |
| 2. WAL durability/recovery | Flush/fsync before acknowledgement; write incremental plain JSONL while retaining legacy compressed readers; recover orphan segments and partial uncommitted tails without overwriting durable data; synchronize ingest, seal, and query. | Immediate search; restart with an unmanifested segment; interrupted final record; injected commit failure and recovery. |
| 3. Durable groups and APIs | Persist event receipts, trace/group state, analyst labels, model configuration, source checkpoints, and decision records in a transactional local SQLite projection; replay WAL receipts missing from that projection; export the existing BLAKE3 JSONL ledger atomically. Add trace, group, timeline, review, and ledger verification HTTP routes. | Restart preserves results and decisions; exported ledger verifies; group review is persisted and audited. |
| 4. Global membership limit | Enforce the configured cap during seeding and assignment across existing memberships; retain analyst decisions and avoid transitive closure. | Seeding and repeated assignments never exceed three active memberships. |
| 5. Consistent filtering | Evaluate filters on WAL and unindexed/fallback results using the same event schema; preserve failures and identify fallback search mode. | Host/time filters exclude mismatches in sealed, live, and fallback paths; malformed filters fail visibly. |
| 6. Structured analytics | Add read-only, bounded SQL over events, traces, groups, memberships, source checkpoints, and decisions; expose CLI and HTTP queries without mandatory search text. | GROUP BY, time-range queries, and membership joins work before and after sealing/restart; writes and external-file SQL are rejected. |
| 7. Resume/idempotency | Persist source sequence checkpoints and content receipts; assign sequences when absent; deduplicate stable content/event IDs and explicit source sequence identities; reject conflicting sequence reuse. | Identical retries do not grow WAL/traces/groups; explicit sequence conflicts return 409; checkpoints survive restart. |
| 8. Honest failures | Validate complete batches before writing; return structured 400/409/500 errors; report failed index creation and search execution instead of success-shaped responses; expose accurate status counts. | Invalid JSON/records/filters, injected disk/index failures, and internal errors produce distinguishable non-success responses. |

## Scoring contract

Use the existing feature, retrieval, queue, and group modules. Default live scoring
is an explicitly identified conservative evidence baseline; it does not claim
to be calibrated against real-world labels. Add supervised model training from
supplied trace-pair labels using the existing logistic/isotonic model, persist its
parameters, and record the scoring mode/model identity in the decision ledger.
Do not silently train on synthetic demo labels or invent attribution truth.

## Sequence

1. Commit this plan before implementation.
2. Implement durable WAL, normalized evidence preservation, and invariant fixes.
3. Implement transactional runtime projection, idempotent ingest, live grouping,
   model training, persistence, and audited analyst review.
4. Implement consistent search/SQL and HTTP/CLI integration with explicit errors.
5. Add regression and HTTP integration tests for all eight acceptance rows.
6. Run the full repository and vendored checks, then exercise a running HTTP
   service through ingest, immediate search, grouping, SQL, review, sealing,
   retry, restart, and ledger verification.
7. Update user documentation and this plan with actual results; commit the
   implementation, tests, and documentation using explicit file paths.

## Initial evidence

- Existing focused ingest/trace/retrieval/group checks: 40 passed.
- Existing HTTP integration test fails at immediate WAL search: zero hits after
  successful ingestion.
- A readable unmanifested WAL tail is overwritten by a restarted writer.
- BM25 WAL hits bypass a host filter.
- Repeated seeding places one trace in four groups despite the configured cap.

## Completion evidence

Pending implementation and verification.
