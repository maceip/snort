"""Transactional projection of durable events into live traces and groups.

WAL is authoritative. SQLite stores receipts and a replayable projection, while
the existing BLAKE3 ledger is exported for independent verification.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

import numpy as np
import pyarrow as pa

from snort.group import Group, GroupManager, Membership, ScoredLink
from snort.errors import ConflictError, NotFoundError, RequestError
from snort.ingest.events import canonical_bytes, event_hash, hash_bytes, normalize_event
from snort.ingest.wal import WalReader
from snort.ledger.chain import Ledger, LedgerRecord
from snort.match.features import PairFeatureContext, pair_cost, pair_features
from snort.match.pair_model import CalibratedPairModel
from snort.match.queue import BestFirstQueue
from snort.persistence import atomic_write
from snort.retrieve.candidates import CandidateRetriever
from snort.retrieve.indicators import IndicatorIndex
from snort.retrieve.minhash_lsh import MinHashLSHIndex
from snort.retrieve.provenance import ProvenanceGraph
from snort.trace.assembler import Trace as AssembledTrace, TraceAssembler
from snort.trace.signatures import Trace, build_idf


def snapshot_tables(db):
    from snort.store.search import EVENT_SCHEMA

    events = [json.loads(r[0]) for r in db.execute("SELECT event_json FROM receipts")]
    for event in events:
        event["ts"] = datetime.fromisoformat(event["ts"].replace("Z", "+00:00"))
    schema = pa.schema(
        [
            pa.field(f.name, pa.timestamp("us", tz="UTC") if f.name == "ts" else f.type)
            for f in EVENT_SCHEMA
        ]
    )
    tables = {"events": pa.Table.from_pylist(events, schema=schema)}
    for name in (
        "traces",
        "trace_events",
        "groups",
        "memberships",
        "decisions",
        "source_checkpoints",
    ):
        info = db.execute(f"PRAGMA table_info({name})").fetchall()
        schema = pa.schema(
            [
                (
                    r[1],
                    pa.int64()
                    if r[2] == "INTEGER"
                    else pa.float64()
                    if r[2] == "DOUBLE"
                    else pa.string(),
                )
                for r in info
            ]
        )
        cursor = db.execute(f"SELECT * FROM {name}")
        columns = [d[0] for d in cursor.description]
        tables[name] = pa.Table.from_pylist(
            [dict(zip(columns, r)) for r in cursor.fetchall()], schema=schema
        )
    return tables


def parsed_attributes(event: dict) -> dict:
    return json.loads(event.get("attributes", "{}"))


def adapt_event(event: dict) -> dict:
    attrs = parsed_attributes(event)
    ts = datetime.fromisoformat(event["ts"].replace("Z", "+00:00")).timestamp()
    evidence_fields = {
        "session_id",
        "beacon_id",
        "session_root",
        "root_pid",
        "tokens",
        "technique_ids",
        "techniques",
        "indicators",
        "entities",
    }
    # Attributes may carry evidence, but cannot replace stored event identity.
    adapted = dict(event, **{k: v for k, v in attrs.items() if k in evidence_fields})
    adapted["ts"] = ts
    for key in ("subject", "object"):
        try:
            adapted[key] = json.loads(event[key])
        except (ValueError, TypeError):
            adapted[key] = event[key]
    adapted["tokens"] = attrs.get("tokens") or re.findall(
        r"[a-z0-9_./:\-]+", event["raw"].lower()
    )
    if not isinstance(adapted["tokens"], list) or any(
        not isinstance(t, str) for t in adapted["tokens"]
    ):
        raise ValueError("tokens must be a list of strings")
    for key in ("technique_ids", "techniques", "entities"):
        value = adapted.get(key, [])
        if not isinstance(value, (str, list, tuple)):
            raise ValueError(f"{key} must be a string or list")
        if isinstance(value, (list, tuple)) and any(
            not isinstance(v, str) for v in value
        ):
            raise ValueError(f"{key} must contain strings")
    indicators = adapted.get("indicators", {})
    if not isinstance(indicators, dict):
        raise ValueError("indicators must map indicator types to values")
    return adapted


class LiveRuntime:
    def __init__(self, data_dir: Path, ledger_file: Path):
        self.ledger_file = ledger_file
        self.db = sqlite3.connect(
            data_dir / "runtime.sqlite3", isolation_level=None, check_same_thread=False
        )
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS receipts (event_hash TEXT PRIMARY KEY, identity_key TEXT UNIQUE NOT NULL,
                content_hash TEXT NOT NULL, source_id TEXT NOT NULL, source_seq INTEGER NOT NULL, event_json TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS source_identity ON receipts(source_id, source_seq);
            CREATE TABLE IF NOT EXISTS source_checkpoints (source_id TEXT PRIMARY KEY, max_seq INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS request_receipts (request_id TEXT PRIMARY KEY, content_hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS traces (trace_id TEXT PRIMARY KEY, anchor TEXT, start_ts DOUBLE,
                end_ts DOUBLE, event_count INTEGER, state TEXT, version INTEGER, features TEXT);
            CREATE TABLE IF NOT EXISTS groups (group_id TEXT PRIMARY KEY, version INTEGER, member_count INTEGER);
            CREATE TABLE IF NOT EXISTS trace_events (trace_id TEXT, event_hash TEXT, PRIMARY KEY(trace_id,event_hash));
            CREATE TABLE IF NOT EXISTS memberships (trace_id TEXT, group_id TEXT, strength DOUBLE,
                state TEXT, version INTEGER, evidence TEXT, PRIMARY KEY(trace_id,group_id));
            CREATE TABLE IF NOT EXISTS decisions (seq INTEGER PRIMARY KEY, kind TEXT, record_hash TEXT,
                prev_hash TEXT, context TEXT, inputs_hash TEXT, model_hash TEXT, params_hash TEXT, output_hash TEXT);
        """)
        self.restore()

    def restore(self):
        saved = self.db.execute("SELECT payload FROM state WHERE id=1").fetchone()
        state = json.loads(saved[0]) if saved else {}
        self.assembler = TraceAssembler()
        for item in state.get("traces", []):
            trace = AssembledTrace.from_dict(item)
            if trace.state == "open":
                self.assembler._open[trace.anchor] = trace
            else:
                self.assembler._sealed.append(trace)
        self.assembler._anchor_counts = state.get("anchor_counts", {})
        self.metadata = state.get("metadata", {})
        self.groups = GroupManager()
        self.groups._next_group = state.get("next_group", 1)
        for item in state.get("groups", []):
            group = Group(item["group_id"], version=item["version"])
            group.members = {
                tid: Membership(**member) for tid, member in item["members"].items()
            }
            self.groups.groups[group.group_id] = group
        self.groups.analyst_labels = {
            (a, b): decision for a, b, decision in state.get("analyst_labels", [])
        }
        self.links = {
            tuple(sorted((link["a"], link["b"]))): link
            for link in state.get("links", [])
        }
        self.ledger = Ledger()
        self.ledger.records = [
            LedgerRecord.from_dict(record) for record in state.get("ledger", [])
        ]
        ok, errors = self.ledger.verify()
        if not ok:
            raise ValueError("runtime ledger verification failed: " + "; ".join(errors))
        self.model = None
        self.model_state = state.get("model")
        if self.model_state:
            self.model = CalibratedPairModel()
            self.model.clf.coef_ = np.asarray([self.model_state["coef"]])
            self.model.clf.intercept_ = np.asarray([self.model_state["intercept"]])
            self.model.calibrator.fit(
                self.model_state["cal_x"], self.model_state["cal_y"]
            )
            self.model._fitted = True
        self._rebuild_indexes()

    @property
    def scoring_mode(self):
        return "logistic-isotonic" if self.model else "evidence-baseline"

    def _matching_trace(self, trace):
        meta = self.metadata[trace.trace_id]
        indicators = frozenset(
            f"{kind}:{value}"
            for kind, values in trace.features.indicators.items()
            for value in values
        )
        return Trace(
            trace.trace_id,
            tuple(meta["tokens"]),
            frozenset(trace.features.technique_tags),
            indicators,
            frozenset(meta["entities"]),
            trace.start_ts or 0.0,
            trace.end_ts or 0.0,
        )

    def _rebuild_indexes(self):
        self.matching = {}
        self.lsh, self.indicators, self.provenance = (
            MinHashLSHIndex(),
            IndicatorIndex(),
            ProvenanceGraph(),
        )
        self.retriever = CandidateRetriever(self.lsh, self.indicators, self.provenance)
        for trace in self.assembler.all_traces():
            matched = self._matching_trace(trace)
            self.matching[trace.trace_id] = matched
            self.retriever.index_trace(matched)

    def prepare(self, records, default_source="http", request_key=None):
        if not isinstance(records, list) or not records:
            raise ValueError("ingest requires a nonempty list of records")
        request_hash = hash_bytes(canonical_bytes(records))
        request_id = f"{default_source}:{request_key}" if request_key else None
        if request_key:
            if not isinstance(request_key, str) or len(request_key) > 256:
                raise ValueError("Idempotency-Key must be at most 256 characters")
            old = self.db.execute(
                "SELECT content_hash FROM request_receipts WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if old and old[0] != request_hash:
                raise ConflictError(
                    "Idempotency-Key was already used for a different batch"
                )
        prepared, pending, next_seq, duplicates = [], {}, {}, 0
        for index, raw in enumerate(records):
            if not isinstance(raw, dict):
                raise ValueError(f"record {index}: expected an object")
            raw = dict(raw)
            attrs = raw.get("attributes") or {}
            if isinstance(attrs, dict) and "_snort_ingest" in attrs:
                raise ValueError("_snort_ingest is reserved")
            source = str(raw.get("source_id") or default_source)
            raw["source_id"] = source
            explicit_seq = "source_seq" in raw
            normalized = normalize_event(raw)
            adapt_event(normalized)  # validate the downstream schema before any write
            content = {
                k: v
                for k, v in normalized.items()
                if k not in ("event_hash", "ingest_ts", "source_seq")
            }
            content_hash = hash_bytes(canonical_bytes(content))
            event_id = raw.get(
                "event_id", attrs.get("event_id") if isinstance(attrs, dict) else None
            )
            if request_key:
                identity = f"request:{source}:{request_key}:{index}"
            elif event_id is not None:
                identity = f"event:{source}:{event_id}"
            elif explicit_seq:
                identity = f"sequence:{source}:{normalized['source_seq']}"
            else:
                identity = f"content:{source}:{content_hash}"
            old = self.db.execute(
                "SELECT content_hash FROM receipts WHERE identity_key=?", (identity,)
            ).fetchone()
            prior = old[0] if old else pending.get(identity)
            if prior is not None:
                if prior != content_hash:
                    raise ConflictError(
                        f"record {index}: identity was already used for different content"
                    )
                duplicates += 1
                continue
            if source not in next_seq:
                checkpoint = self.db.execute(
                    "SELECT max_seq FROM source_checkpoints WHERE source_id=?",
                    (source,),
                ).fetchone()
                next_seq[source] = checkpoint[0] + 1 if checkpoint else 0
            if not explicit_seq:
                normalized["source_seq"] = next_seq[source]
            seq = normalized["source_seq"]
            if not 0 <= seq < 2**63:
                raise ValueError(
                    "source sequence has exceeded the supported integer range"
                )
            occupied = self.db.execute(
                "SELECT content_hash FROM receipts WHERE source_id=? AND source_seq=?",
                (source, seq),
            ).fetchone()
            if occupied:
                if occupied[0] != content_hash:
                    raise ConflictError(
                        f"record {index}: source sequence conflicts with existing content"
                    )
                duplicates += 1
                continue
            if any(
                e["source_id"] == source and e["source_seq"] == seq for e in prepared
            ):
                raise ConflictError(
                    f"record {index}: source sequence appears twice in this batch"
                )
            next_seq[source] = max(next_seq[source], seq + 1)
            event_attrs = parsed_attributes(normalized)
            event_attrs["_snort_ingest"] = {
                "key": identity,
                "content_hash": content_hash,
            }
            if request_id:
                event_attrs["_snort_ingest"].update(
                    request_id=request_id, request_hash=request_hash
                )
            normalized["attributes"] = canonical_bytes(event_attrs).decode()
            normalized["event_hash"] = event_hash(normalized)
            pending[identity] = content_hash
            prepared.append(normalized)
        return prepared, duplicates

    def recover(self, wal_dir):
        pending, seen = [], set()
        for event in WalReader(wal_dir).iter_events():
            if (
                event["event_hash"] not in seen
                and not self.db.execute(
                    "SELECT 1 FROM receipts WHERE event_hash=?", (event["event_hash"],)
                ).fetchone()
            ):
                pending.append(event)
                seen.add(event["event_hash"])
        if pending:
            self.apply(pending)
        self.export_ledger()

    def apply(self, events):
        if not events:
            return
        self.db.execute("BEGIN IMMEDIATE")
        try:
            changed = set()
            for event in events:
                attrs = parsed_attributes(event)
                receipt = attrs.get(
                    "_snort_ingest",
                    {
                        "key": "legacy:" + event["event_hash"],
                        "content_hash": event["event_hash"],
                    },
                )
                if receipt.get("request_id"):
                    self.db.execute(
                        "INSERT OR IGNORE INTO request_receipts VALUES (?,?)",
                        (receipt["request_id"], receipt["request_hash"]),
                    )
                self.db.execute(
                    "INSERT INTO receipts VALUES (?,?,?,?,?,?)",
                    (
                        event["event_hash"],
                        receipt["key"],
                        receipt["content_hash"],
                        event["source_id"],
                        event["source_seq"],
                        json.dumps(event),
                    ),
                )
                self.db.execute(
                    "INSERT INTO source_checkpoints VALUES (?,?) ON CONFLICT(source_id) DO UPDATE SET max_seq=MAX(max_seq,excluded.max_seq)",
                    (event["source_id"], event["source_seq"]),
                )
                adapted = adapt_event(event)
                trace = self.assembler.ingest(adapted)
                meta = self.metadata.setdefault(
                    trace.trace_id, {"tokens": [], "entities": []}
                )
                meta["tokens"] = (meta["tokens"] + adapted["tokens"])[-4096:]
                entities = adapted.get("entities", [])
                if isinstance(entities, str):
                    entities = [entities]
                entities = list(entities) + [
                    str(adapted.get("subject", "")),
                    str(adapted.get("object", "")),
                ]
                meta["entities"] = sorted(
                    set(meta["entities"]) | {e for e in entities if e}
                )
                changed.add(trace.trace_id)
            self._rebuild_indexes()
            self.ledger.append(
                "ingest",
                [e["event_hash"] for e in events],
                {"runtime": 1},
                {},
                {"events": len(events)},
                sorted(changed),
            )
            for tid in sorted(changed):
                self._group_trace(tid)
            self.persist()
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            self.restore()
            raise
        self.export_ledger()

    def _context(self):
        return PairFeatureContext(
            build_idf([t.token_counts for t in self.matching.values()]),
            self.indicators,
            self.provenance,
        )

    def _group_trace(self, tid):
        trace, context = self.matching[tid], self._context()
        candidates = self.retriever.retrieve(trace)
        queue = BestFirstQueue()
        for candidate in candidates:
            queue.push(
                tid,
                candidate.trace_id,
                candidate.estimate,
                pair_cost(trace, self.matching[candidate.trace_id]),
            )
        jobs = queue.pop_round()
        touched = {tid}
        for _, other_id, estimate in jobs:
            other = self.matching[other_id]
            feats = pair_features(trace, other, context)
            score = (
                float(self.model.predict_proba([feats])[0])
                if self.model
                else min(
                    1.0,
                    0.45 * feats[0]
                    + 0.30 * feats[1]
                    + 0.15 * min(1, feats[6])
                    + 0.10 * feats[3],
                )
            )
            classes = []
            for cls, supported in (
                ("behavior", feats[0] >= 0.4),
                ("execution", feats[1] >= 0.5),
                ("infrastructure", feats[6] > 0),
                ("technique", feats[3] > 0),
                ("provenance", feats[4] > 0),
            ):
                if supported:
                    classes.append(cls)
            contributions = (
                self.model.contributions(feats)
                if self.model
                else {
                    "minhash_jaccard": 0.45 * feats[0],
                    "tfidf_cosine": 0.30 * feats[1],
                    "shared_indicator_count": 0.15 * min(1, feats[6]),
                    "technique_jaccard": 0.10 * feats[3],
                }
            )
            hashes = (
                self.assembler.get(tid).member_event_hashes
                + self.assembler.get(other_id).member_event_hashes
            )
            link = {
                "a": tid,
                "b": other_id,
                "score": score,
                "evidence_classes": classes,
                "contributions": contributions,
                "shared_shingles": sorted(trace.shingles & other.shingles)[:20],
                "shared_indicators": sorted(trace.indicators & other.indicators),
                "event_hashes": hashes,
                "scoring_mode": self.scoring_mode,
            }
            self.links[tuple(sorted((tid, other_id)))] = link
            self.groups.maybe_seed(tid, other_id, score, classes, evidence=link)
            touched.add(other_id)
            self.ledger.append(
                "link",
                [tid, other_id],
                {"mode": self.scoring_mode, "model": self.model_state},
                {"seed": 0.8},
                {"estimate": estimate},
                link,
            )
        for touched_id in sorted(touched):
            links_by_group = {}
            for gid, group in self.groups.groups.items():
                links = []
                for member_id, member in group.members.items():
                    if member_id == touched_id or member.state == "analyst-rejected":
                        continue
                    link = self.links.get(tuple(sorted((touched_id, member_id))))
                    if link:
                        links.append(
                            ScoredLink(
                                member_id,
                                link["score"],
                                tuple(link["evidence_classes"]),
                                link["contributions"],
                                tuple(link["shared_shingles"]),
                                tuple(link["shared_indicators"]),
                                tuple(link["event_hashes"]),
                            )
                        )
                if links:
                    links_by_group[gid] = links
            self.groups.assign(touched_id, links_by_group)
        self.ledger.append(
            "groups",
            sorted(touched),
            {"mode": self.scoring_mode},
            {"max_memberships": 3},
            {},
            {t: self.groups.groups_of(t) for t in sorted(touched)},
        )

    def persist(self):
        state = {
            "traces": [t.to_dict() for t in self.assembler.all_traces()],
            "anchor_counts": self.assembler._anchor_counts,
            "metadata": self.metadata,
            "groups": [asdict(g) for g in self.groups.groups.values()],
            "next_group": self.groups._next_group,
            "analyst_labels": [
                [a, b, d] for (a, b), d in self.groups.analyst_labels.items()
            ],
            "links": list(self.links.values()),
            "ledger": [r.to_dict() for r in self.ledger.records],
            "model": self.model_state,
        }
        self.db.execute(
            "INSERT OR REPLACE INTO state VALUES (1,?)", (json.dumps(state),)
        )
        for table in ("traces", "trace_events", "groups", "memberships", "decisions"):
            self.db.execute(f"DELETE FROM {table}")
        for trace in self.assembler.all_traces():
            self.db.execute(
                "INSERT INTO traces VALUES (?,?,?,?,?,?,?,?)",
                (
                    trace.trace_id,
                    trace.anchor,
                    trace.start_ts,
                    trace.end_ts,
                    trace.event_count,
                    trace.state,
                    trace.version,
                    json.dumps(trace.features.to_dict()),
                ),
            )
            self.db.executemany(
                "INSERT INTO trace_events VALUES (?,?)",
                [(trace.trace_id, h) for h in trace.member_event_hashes],
            )
        for group in self.groups.groups.values():
            count = sum(m.state != "analyst-rejected" for m in group.members.values())
            self.db.execute(
                "INSERT INTO groups VALUES (?,?,?)",
                (group.group_id, group.version, count),
            )
            for member in group.members.values():
                self.db.execute(
                    "INSERT INTO memberships VALUES (?,?,?,?,?,?)",
                    (
                        member.trace_id,
                        member.group_id,
                        member.strength,
                        member.state,
                        member.version,
                        json.dumps(member.evidence),
                    ),
                )
        for record in self.ledger.records:
            self.db.execute(
                "INSERT INTO decisions VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    record.seq,
                    record.kind,
                    record.record_hash,
                    record.prev_hash,
                    json.dumps(record.context),
                    record.inputs_hash,
                    record.model_hash,
                    record.params_hash,
                    record.output_hash,
                ),
            )

    def export_ledger(self):
        atomic_write(
            self.ledger_file,
            "".join(
                json.dumps(r.to_dict(), sort_keys=True) + "\n"
                for r in self.ledger.records
            ),
        )

    def review(self, trace_id, group_id, decision):
        if decision not in ("analyst-confirmed", "analyst-rejected"):
            raise RequestError("decision must be analyst-confirmed or analyst-rejected")
        if (
            group_id not in self.groups.groups
            or trace_id not in self.groups.groups[group_id].members
        ):
            raise NotFoundError("trace-group membership not found")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            try:
                member = self.groups.analyst_decide(trace_id, group_id, decision)
            except ValueError as exc:
                raise ConflictError(str(exc)) from exc
            self.ledger.append(
                "analyst-review",
                [trace_id, group_id],
                {"review": 1},
                {},
                {},
                asdict(member),
            )
            self.persist()
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            self.restore()
            raise
        self.export_ledger()
        return asdict(member)

    def train(self, labels):
        if not isinstance(labels, list) or not labels:
            raise RequestError("pairs must be a nonempty list")
        features, outcomes = [], []
        context = self._context()
        for label in labels:
            if not isinstance(label, dict) or not all(
                k in label for k in ("a", "b", "match")
            ):
                raise RequestError("each pair needs a, b, and match fields")
            if not isinstance(label["a"], str) or not isinstance(label["b"], str):
                raise RequestError("trace IDs must be strings")
            if label["a"] not in self.matching or label["b"] not in self.matching:
                raise NotFoundError("training trace not found")
            a, b = self.matching[label["a"]], self.matching[label["b"]]
            y = label["match"]
            if y not in (0, 1, False, True):
                raise RequestError("match labels must be 0 or 1")
            features.append(pair_features(a, b, context))
            outcomes.append(int(y))
        try:
            model = CalibratedPairModel().fit(features, outcomes)
        except ValueError as exc:
            raise RequestError(str(exc)) from exc
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.model = model
            self.model_state = {
                "coef": model.clf.coef_[0].tolist(),
                "intercept": float(model.clf.intercept_[0]),
                "cal_x": model.calibrator.X_thresholds_.tolist(),
                "cal_y": model.calibrator.y_thresholds_.tolist(),
            }
            self.ledger.append(
                "model-training",
                labels,
                model.decision_context(),
                {},
                {"pairs": len(labels)},
                self.model_state,
            )
            for tid in sorted(self.matching):
                self._group_trace(tid)
            self.persist()
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            self.restore()
            raise
        self.export_ledger()
        return {
            "mode": self.scoring_mode,
            "pairs": len(labels),
            **model.decision_context(),
        }

    def table(self, name):
        if name not in (
            "traces",
            "trace_events",
            "groups",
            "memberships",
            "decisions",
            "source_checkpoints",
        ):
            raise ValueError("unknown runtime table")
        cursor = self.db.execute(f"SELECT * FROM {name}")
        columns = [d[0] for d in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def close(self):
        self.db.close()
