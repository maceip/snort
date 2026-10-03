"""Embedded single-process HTTP server and network ingest sink for snort."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from snort.errors import ConflictError, NotFoundError, RequestError
from snort.ingest.otlp import parse_otlp_logs, parse_otlp_traces
from snort.ingest.wal import WalWriter
from snort.store.index import build_index
from snort.store.seal import seal_segments
from snort.store.search import search


class SnortStoreManager:
    """Single writer for durable WAL and transactional live projections."""

    def __init__(
        self,
        data_dir,
        *,
        wal_dir=None,
        sealed_dir=None,
        index_dir=None,
        max_bytes=64 * 1024 * 1024,
    ):
        from snort.runtime import LiveRuntime

        self.data_dir = Path(data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.wal_dir = Path(wal_dir).resolve() if wal_dir else self.data_dir / "wal"
        self.sealed_dir, self.index_dir = (
            self.data_dir / "sealed",
            self.data_dir / "index",
        )
        if sealed_dir:
            self.sealed_dir = Path(sealed_dir).resolve()
        if index_dir:
            self.index_dir = Path(index_dir).resolve()
        self.ledger_file = self.data_dir / "ledger" / "ledger.jsonl"
        self.lock = threading.RLock()
        self._writer_lock = open(self.data_dir / ".writer.lock", "a+b")
        try:
            if os.name == "nt":
                import msvcrt

                self._writer_lock.seek(0)
                self._writer_lock.write(b"0")
                self._writer_lock.flush()
                self._writer_lock.seek(0)
                msvcrt.locking(self._writer_lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._writer_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            for path in (
                self.wal_dir,
                self.sealed_dir,
                self.index_dir,
                self.ledger_file.parent,
            ):
                path.mkdir(parents=True, exist_ok=True)
            self.max_bytes = max_bytes
            self.wal_writer = WalWriter(self.wal_dir, max_bytes=max_bytes)
            self.runtime = LiveRuntime(self.data_dir, self.ledger_file)
            self.runtime.recover(self.wal_dir)
        except Exception:
            if hasattr(self, "wal_writer"):
                self.wal_writer.abort()
            if hasattr(self, "runtime"):
                self.runtime.close()
            self._writer_lock.close()
            raise
        self._recover_needed = False
        self._closed = False

    def _recover(self):
        if self._recover_needed:
            self.wal_writer.abort()
            self.wal_writer = WalWriter(self.wal_dir, max_bytes=self.max_bytes)
            self.runtime.restore()
            self.runtime.recover(self.wal_dir)
            self._recover_needed = False

    def ingest(self, records, *, source="http", request_key=None):
        with self.lock:
            self._recover()
            try:
                prepared, duplicates = self.runtime.prepare(
                    records, source, request_key
                )
            except ConflictError:
                raise
            except (ValueError, TypeError, OverflowError) as exc:
                raise RequestError(str(exc)) from exc
            try:
                for event in prepared:
                    self.wal_writer.append(event)
                self.runtime.apply(prepared)
            except Exception:
                self._recover_needed = True
                raise
            if request_key:
                from snort.ingest.events import canonical_bytes, hash_bytes

                self.runtime.db.execute(
                    "INSERT OR IGNORE INTO request_receipts VALUES (?,?)",
                    (f"{source}:{request_key}", hash_bytes(canonical_bytes(records))),
                )
            return {
                "ok": True,
                "ingested": len(prepared),
                "duplicates": duplicates,
                "event_hashes": [e["event_hash"] for e in prepared],
                "scoring_mode": self.runtime.scoring_mode,
            }

    def ingest_records(self, records):
        return self.ingest(records)["ingested"]

    def seal_and_index(self):
        with self.lock:
            self._recover()
            try:
                self.wal_writer.roll()
                sealed = seal_segments(self.wal_dir, self.sealed_dir)
                indexed = build_index(self.sealed_dir, self.index_dir)
            except Exception:
                self._recover_needed = True
                raise
            return {
                "sealed": [e["name"] for e in sealed],
                "sealed_count": sum(e["count"] for e in sealed),
                "indexed": [e["segment"] for e in indexed],
            }

    def seal(self):
        with self.lock:
            self._recover()
            self.wal_writer.roll()
            return seal_segments(self.wal_dir, self.sealed_dir)

    def search_events(self, query, limit=100, bm25=False, filter_expr=None):
        with self.lock:
            self._recover()
            return search(
                query,
                self.sealed_dir,
                self.index_dir,
                self.wal_dir,
                limit=limit,
                bm25=bm25,
                filter_expr=filter_expr,
            )

    def query(self, sql, limit=1000):
        from snort.runtime import snapshot_tables
        from snort.store.search import query_tables

        with self.lock:
            self._recover()
            return query_tables(sql, snapshot_tables(self.runtime.db), limit=limit)

    def traces(self):
        with self.lock:
            self._recover()
            return [
                dict(t.to_dict(), groups=self.runtime.groups.groups_of(t.trace_id))
                for t in self.runtime.assembler.all_traces()
            ]

    def groups(self, group_id=None):
        from dataclasses import asdict

        with self.lock:
            self._recover()
            groups = self.runtime.groups.groups
            if group_id is not None:
                if group_id not in groups:
                    raise NotFoundError(group_id)
                group = groups[group_id]
                spans = {
                    t.trace_id: (t.start_ts, t.end_ts)
                    for t in self.runtime.assembler.all_traces()
                }
                return dict(
                    asdict(group),
                    timeline=self.runtime.groups.group_timeline(group_id, spans),
                    scoring_mode=self.runtime.scoring_mode,
                )
            return [asdict(g) for g in groups.values()]

    def review(self, group_id, trace_id, decision):
        if not isinstance(trace_id, str) or not isinstance(decision, str):
            raise RequestError("review fields must be strings")
        with self.lock:
            self._recover()
            try:
                return self.runtime.review(trace_id, group_id, decision)
            except (RequestError, NotFoundError):
                raise
            except Exception:
                self._recover_needed = True
                raise

    def train(self, pairs):
        with self.lock:
            self._recover()
            try:
                return self.runtime.train(pairs)
            except (RequestError, NotFoundError):
                raise
            except Exception:
                self._recover_needed = True
                raise

    def verify_ledger(self):
        from snort.ledger.chain import Ledger

        with self.lock:
            self._recover()
            disk = Ledger.load(str(self.ledger_file))
            ok, errors = disk.verify()
            if (
                len(disk) != len(self.runtime.ledger)
                or disk.head() != self.runtime.ledger.head()
            ):
                ok = False
                errors.append("export differs from committed ledger head")
            return {
                "ok": ok,
                "records": len(disk),
                "head": disk.head(),
                "errors": errors,
            }

    def get_services(self) -> list[dict]:
        with self.lock:
            self._recover()
            rows = self.runtime.db.execute("SELECT event_json FROM receipts").fetchall()
            services: dict[str, dict] = {}
            for r in rows:
                try:
                    ev = json.loads(r[0])
                    svc = ev.get("source_id") or "unknown_service"
                    attrs = (
                        json.loads(ev.get("attributes", "{}"))
                        if isinstance(ev.get("attributes"), str)
                        else (ev.get("attributes") or {})
                    )
                    entry = services.setdefault(
                        svc, {"name": svc, "events": 0, "errors": 0, "ai_calls": 0}
                    )
                    entry["events"] += 1
                    if (
                        attrs.get("status") == "error"
                        or ev.get("action", "").startswith("log.error")
                    ):
                        entry["errors"] += 1
                    if attrs.get("is_ai_call"):
                        entry["ai_calls"] += 1
                except Exception:
                    pass
            result = list(services.values())
            result.sort(key=lambda x: x["events"], reverse=True)
            return result

    def get_traces_summary(
        self, service: str | None = None, status: str | None = None, limit: int = 100
    ) -> list[dict]:
        with self.lock:
            self._recover()
            rows = self.runtime.db.execute("SELECT event_json FROM receipts").fetchall()
            trace_events: dict[str, list[tuple[dict, dict]]] = {}
            for r in rows:
                try:
                    ev = json.loads(r[0])
                    attrs = (
                        json.loads(ev.get("attributes", "{}"))
                        if isinstance(ev.get("attributes"), str)
                        else (ev.get("attributes") or {})
                    )
                    tid = (
                        attrs.get("trace_id")
                        or ev.get("session_id")
                        or ev.get("subject")
                    )
                    if tid:
                        trace_events.setdefault(tid, []).append((ev, attrs))
                except Exception:
                    pass

            summaries = []
            for tid, ev_pairs in trace_events.items():
                spans_only = [
                    p for p in ev_pairs if not p[0].get("action", "").startswith("log.")
                ]
                if not spans_only:
                    spans_only = ev_pairs

                spans_only.sort(key=lambda p: p[0].get("ts", ""))
                first_ev, first_attrs = spans_only[0]
                last_ev, last_attrs = spans_only[-1]

                svc = (
                    first_ev.get("source_id")
                    or first_attrs.get("service_name")
                    or "unknown"
                )
                root_op = first_ev.get("action") or "operation"
                for ev, attrs in spans_only:
                    if not attrs.get("parent_span_id"):
                        root_op = ev.get("action") or root_op
                        svc = ev.get("source_id") or svc
                        break

                err_count = sum(
                    1
                    for ev, attrs in spans_only
                    if attrs.get("status") == "error"
                    or ev.get("action", "").startswith("log.error")
                )
                ai_count = sum(
                    1 for ev, attrs in spans_only if attrs.get("is_ai_call")
                )
                trace_status = "error" if err_count > 0 else "ok"

                if service and svc != service:
                    continue
                if status and trace_status != status.lower():
                    continue

                try:
                    t0 = (
                        datetime.fromisoformat(
                            first_ev.get("ts", "").replace("Z", "+00:00")
                        ).timestamp()
                        * 1000.0
                    )
                    t1 = (
                        datetime.fromisoformat(
                            last_ev.get("ts", "").replace("Z", "+00:00")
                        ).timestamp()
                        * 1000.0
                    )
                    last_duration = float(last_attrs.get("duration_ms", 0.0))
                    duration_ms = round(
                        max(
                            float(first_attrs.get("duration_ms", 0.0)),
                            (t1 - t0) + last_duration,
                        ),
                        2,
                    )
                except Exception:
                    duration_ms = float(first_attrs.get("duration_ms", 0.0))

                summaries.append(
                    {
                        "trace_id": tid,
                        "service": svc,
                        "root_operation": root_op,
                        "start_ts": first_ev.get("ts"),
                        "end_ts": last_ev.get("ts"),
                        "duration_ms": duration_ms,
                        "span_count": len(spans_only),
                        "error_count": err_count,
                        "ai_call_count": ai_count,
                        "status": trace_status,
                    }
                )

            summaries.sort(key=lambda x: x["start_ts"] or "", reverse=True)
            return summaries[:limit]

    def get_trace_tree(self, trace_id: str) -> dict | None:
        with self.lock:
            self._recover()
            target_hashes = set()
            for t in self.runtime.assembler.all_traces():
                if (
                    t.trace_id == trace_id
                    or trace_id in t.trace_id
                    or trace_id in t.anchor
                ):
                    target_hashes.update(t.member_event_hashes)

            rows = self.runtime.db.execute(
                "SELECT event_hash, event_json FROM receipts"
            ).fetchall()
            matching_events = []
            for h, j_str in rows:
                if h in target_hashes:
                    matching_events.append(json.loads(j_str))
                    continue
                try:
                    ev = json.loads(j_str)
                    attrs = (
                        json.loads(ev.get("attributes", "{}"))
                        if isinstance(ev.get("attributes"), str)
                        else (ev.get("attributes") or {})
                    )
                    if (
                        attrs.get("trace_id") == trace_id
                        or ev.get("session_id") == trace_id
                        or ev.get("subject") == trace_id
                    ):
                        matching_events.append(ev)
                except Exception:
                    pass

            if not matching_events:
                return None

            spans_raw = [
                e
                for e in matching_events
                if not e.get("action", "").startswith("log.")
            ]
            if not spans_raw:
                spans_raw = matching_events
            logs_raw = [
                e for e in matching_events if e.get("action", "").startswith("log.")
            ]

            spans = []
            for e in spans_raw:
                attrs = (
                    json.loads(e.get("attributes", "{}"))
                    if isinstance(e.get("attributes"), str)
                    else (e.get("attributes") or {})
                )
                spans.append(
                    {
                        "span_id": attrs.get("span_id")
                        or e.get("event_hash", "")[:16],
                        "parent_span_id": attrs.get("parent_span_id") or "",
                        "name": e.get("action") or "span",
                        "service": e.get("source_id")
                        or attrs.get("service_name")
                        or "unknown",
                        "host": e.get("host") or "localhost",
                        "ts": e.get("ts"),
                        "duration_ms": float(attrs.get("duration_ms", 0.0)),
                        "status": attrs.get("status") or "ok",
                        "status_code": attrs.get("status_code", 0),
                        "status_message": attrs.get("status_message", ""),
                        "kind": attrs.get("span_kind", "internal"),
                        "is_ai_call": bool(attrs.get("is_ai_call")),
                        "attributes": attrs,
                        "events": attrs.get("events", []),
                        "raw": e.get("raw", ""),
                    }
                )

            def _parse_ts(ts_str):
                try:
                    return (
                        datetime.fromisoformat(
                            ts_str.replace("Z", "+00:00")
                        ).timestamp()
                        * 1000.0
                    )
                except Exception:
                    return 0.0

            for s in spans:
                s["start_ms"] = _parse_ts(s["ts"])

            spans.sort(key=lambda x: x["start_ms"])
            min_start = min(s["start_ms"] for s in spans)
            max_end = max(s["start_ms"] + s["duration_ms"] for s in spans)
            total_duration_ms = max(0.001, max_end - min_start)

            span_by_id = {s["span_id"]: s for s in spans}
            children_map: dict[str, list[dict]] = {}
            root_spans = []
            for s in spans:
                pid = s["parent_span_id"]
                if pid and pid in span_by_id and pid != s["span_id"]:
                    children_map.setdefault(pid, []).append(s)
                else:
                    root_spans.append(s)

            ordered_spans: list[dict] = []

            def dfs(node, depth):
                node["depth"] = depth
                node["offset_ms"] = round(node["start_ms"] - min_start, 3)
                node["offset_pct"] = round(
                    min(
                        99.0,
                        max(0.0, (node["offset_ms"] / total_duration_ms) * 100.0),
                    ),
                    2,
                )
                node["width_pct"] = round(
                    max(
                        1.0,
                        min(
                            100.0 - node["offset_pct"],
                            (node["duration_ms"] / total_duration_ms) * 100.0,
                        ),
                    ),
                    2,
                )
                node["logs"] = [
                    l
                    for l in logs_raw
                    if (
                        json.loads(l.get("attributes", "{}"))
                        if isinstance(l.get("attributes"), str)
                        else l.get("attributes", {})
                    ).get("span_id")
                    == node["span_id"]
                ]
                ordered_spans.append(node)
                for child in sorted(
                    children_map.get(node["span_id"], []), key=lambda c: c["start_ms"]
                ):
                    dfs(child, depth + 1)

            for r in root_spans:
                dfs(r, 0)

            errors_count = sum(1 for s in spans if s["status"] == "error")
            ai_calls_count = sum(1 for s in spans if s.get("is_ai_call"))

            return {
                "trace_id": trace_id,
                "service": ordered_spans[0]["service"] if ordered_spans else "unknown",
                "root_operation": ordered_spans[0]["name"]
                if ordered_spans
                else "unknown",
                "start_ts": ordered_spans[0]["ts"] if ordered_spans else "",
                "duration_ms": round(total_duration_ms, 3),
                "span_count": len(ordered_spans),
                "error_count": errors_count,
                "ai_call_count": ai_calls_count,
                "status": "error" if errors_count > 0 else "ok",
                "spans": ordered_spans,
                "logs": logs_raw,
            }

    def get_span(self, span_id: str) -> dict | None:
        with self.lock:
            self._recover()
            rows = self.runtime.db.execute("SELECT event_json FROM receipts").fetchall()
            target_span = None
            correlated_logs = []
            for r in rows:
                try:
                    ev = json.loads(r[0])
                    attrs = (
                        json.loads(ev.get("attributes", "{}"))
                        if isinstance(ev.get("attributes"), str)
                        else (ev.get("attributes") or {})
                    )
                    sid = attrs.get("span_id") or ev.get("session_root")
                    if sid == span_id:
                        if ev.get("action", "").startswith("log."):
                            correlated_logs.append(ev)
                        else:
                            target_span = dict(ev, attributes=attrs)
                except Exception:
                    pass
            if target_span:
                target_span["correlated_logs"] = correlated_logs
            return target_span

    def get_ai_calls(
        self,
        limit: int = 100,
        service: str | None = None,
        model: str | None = None,
    ) -> list[dict]:
        with self.lock:
            self._recover()
            rows = self.runtime.db.execute("SELECT event_json FROM receipts").fetchall()
            calls = []
            for r in rows:
                try:
                    ev = json.loads(r[0])
                    attrs = (
                        json.loads(ev.get("attributes", "{}"))
                        if isinstance(ev.get("attributes"), str)
                        else (ev.get("attributes") or {})
                    )
                    if attrs.get("is_ai_call"):
                        svc = (
                            ev.get("source_id")
                            or attrs.get("service_name")
                            or "unknown"
                        )
                        mdl = attrs.get("ai_model") or "unknown"
                        if service and svc != service:
                            continue
                        if model and model.lower() not in mdl.lower():
                            continue
                        calls.append(
                            {
                                "span_id": attrs.get("span_id", ""),
                                "trace_id": attrs.get("trace_id", "")
                                or ev.get("session_id", ""),
                                "service": svc,
                                "operation": ev.get("action", ""),
                                "provider": attrs.get("ai_provider", "unknown"),
                                "model": mdl,
                                "duration_ms": float(attrs.get("duration_ms", 0.0)),
                                "input_tokens": int(attrs.get("ai_input_tokens", 0)),
                                "output_tokens": int(attrs.get("ai_output_tokens", 0)),
                                "total_tokens": int(attrs.get("ai_total_tokens", 0)),
                                "prompt": attrs.get("ai_prompt", ""),
                                "completion": attrs.get("ai_completion", ""),
                                "prompt_preview": attrs.get("ai_prompt_preview", ""),
                                "completion_preview": attrs.get(
                                    "ai_completion_preview", ""
                                ),
                                "status": attrs.get("status", "ok"),
                                "timestamp": ev.get("ts", ""),
                                "attributes": attrs,
                            }
                        )
                except Exception:
                    pass
            calls.sort(key=lambda x: x["timestamp"], reverse=True)
            return calls[:limit]

    def get_logs(
        self,
        service: str | None = None,
        trace_id: str | None = None,
        span_id: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        with self.lock:
            self._recover()
            rows = self.runtime.db.execute("SELECT event_json FROM receipts").fetchall()
            logs = []
            for r in rows:
                try:
                    ev = json.loads(r[0])
                    action = ev.get("action", "")
                    if not action.startswith("log."):
                        continue
                    attrs = (
                        json.loads(ev.get("attributes", "{}"))
                        if isinstance(ev.get("attributes"), str)
                        else (ev.get("attributes") or {})
                    )
                    svc = (
                        ev.get("source_id")
                        or attrs.get("service_name")
                        or "unknown"
                    )
                    tid = attrs.get("trace_id") or ev.get("session_id") or ""
                    sid = attrs.get("span_id") or ""
                    sev = attrs.get("severity") or action.replace("log.", "").upper()

                    if service and svc != service:
                        continue
                    if trace_id and tid != trace_id:
                        continue
                    if span_id and sid != span_id:
                        continue
                    if severity and sev.lower() != severity.lower():
                        continue

                    logs.append(
                        {
                            "ts": ev.get("ts"),
                            "service": svc,
                            "severity": sev,
                            "trace_id": tid,
                            "span_id": sid,
                            "message": ev.get("raw", ""),
                            "attributes": attrs,
                        }
                    )
                except Exception:
                    pass
            logs.sort(key=lambda x: x["ts"] or "", reverse=True)
            return logs[:limit]

    def demo_otlp(self) -> dict:
        now_nano = int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)
        sample_traces = {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "checkout-api"}},
                            {"key": "host.name", "value": {"stringValue": "edge-01"}},
                        ]
                    },
                    "scopeSpans": [
                        {
                            "scope": {"name": "http-server"},
                            "spans": [
                                {
                                    "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
                                    "spanId": "00f067aa0ba902b7",
                                    "name": "POST /api/v1/checkout",
                                    "kind": 2,
                                    "startTimeUnixNano": str(now_nano),
                                    "endTimeUnixNano": str(now_nano + 75_000_000),
                                    "attributes": [
                                        {"key": "http.method", "value": {"stringValue": "POST"}},
                                        {"key": "http.target", "value": {"stringValue": "/api/v1/checkout"}},
                                        {"key": "http.status_code", "value": {"intValue": 200}},
                                    ],
                                    "status": {"code": 1},
                                },
                                {
                                    "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
                                    "spanId": "5fb397be34d23b0f",
                                    "parentSpanId": "00f067aa0ba902b7",
                                    "name": "auth.verify_jwt",
                                    "kind": 1,
                                    "startTimeUnixNano": str(now_nano + 2_000_000),
                                    "endTimeUnixNano": str(now_nano + 8_000_000),
                                    "attributes": [
                                        {"key": "user.id", "value": {"stringValue": "usr_998231"}},
                                        {"key": "auth.scope", "value": {"stringValue": "checkout"}},
                                    ],
                                    "status": {"code": 1},
                                },
                                {
                                    "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
                                    "spanId": "7c8b21ef45a30129",
                                    "parentSpanId": "00f067aa0ba902b7",
                                    "name": "ai.suggest_bundles",
                                    "kind": 3,
                                    "startTimeUnixNano": str(now_nano + 10_000_000),
                                    "endTimeUnixNano": str(now_nano + 55_000_000),
                                    "attributes": [
                                        {"key": "gen_ai.system", "value": {"stringValue": "anthropic"}},
                                        {"key": "gen_ai.request.model", "value": {"stringValue": "claude-3-7-sonnet"}},
                                        {"key": "gen_ai.usage.input_tokens", "value": {"intValue": 240}},
                                        {"key": "gen_ai.usage.output_tokens", "value": {"intValue": 55}},
                                        {"key": "ai.prompt", "value": {"stringValue": "User cart: MacBook Pro M4, 140W USB-C Charger. Suggest 2 high conversion accessories."}},
                                        {"key": "ai.response", "value": {"stringValue": "1. USB-C Travel Adapter Pro (Multi-port)\n2. Water-resistant Laptop Sleeve"}},
                                    ],
                                    "status": {"code": 1},
                                },
                                {
                                    "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
                                    "spanId": "9a1b2c3d4e5f6789",
                                    "parentSpanId": "00f067aa0ba902b7",
                                    "name": "db.save_order",
                                    "kind": 3,
                                    "startTimeUnixNano": str(now_nano + 58_000_000),
                                    "endTimeUnixNano": str(now_nano + 73_000_000),
                                    "attributes": [
                                        {"key": "db.system", "value": {"stringValue": "postgresql"}},
                                        {"key": "db.statement", "value": {"stringValue": "INSERT INTO orders (id, total, status) VALUES ($1, $2, $3)"}},
                                    ],
                                    "status": {"code": 1},
                                },
                            ],
                        }
                    ],
                },
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "auth-service"}},
                            {"key": "host.name", "value": {"stringValue": "auth-01"}},
                        ]
                    },
                    "scopeSpans": [
                        {
                            "scope": {"name": "ldap-client"},
                            "spans": [
                                {
                                    "traceId": "e1f2a3b4c5d6e7f80918273645546372",
                                    "spanId": "a1b2c3d4e5f60718",
                                    "name": "POST /api/v1/login",
                                    "kind": 2,
                                    "startTimeUnixNano": str(now_nano + 100_000_000),
                                    "endTimeUnixNano": str(now_nano + 135_000_000),
                                    "attributes": [
                                        {"key": "http.target", "value": {"stringValue": "/api/v1/login"}},
                                        {"key": "http.status_code", "value": {"intValue": 500}},
                                    ],
                                    "status": {"code": 2, "message": "LDAP connection refused"},
                                },
                                {
                                    "traceId": "e1f2a3b4c5d6e7f80918273645546372",
                                    "spanId": "b2c3d4e5f6a10719",
                                    "parentSpanId": "a1b2c3d4e5f60718",
                                    "name": "ldap.bind",
                                    "kind": 3,
                                    "startTimeUnixNano": str(now_nano + 105_000_000),
                                    "endTimeUnixNano": str(now_nano + 130_000_000),
                                    "attributes": [
                                        {"key": "ldap.server", "value": {"stringValue": "ldap.corp.internal:636"}},
                                    ],
                                    "status": {"code": 2, "message": "Connection timeout after 25ms"},
                                },
                            ],
                        }
                    ],
                },
            ]
        }
        sample_logs = {
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [{"key": "service.name", "value": {"stringValue": "auth-service"}}]
                    },
                    "scopeLogs": [
                        {
                            "logRecords": [
                                {
                                    "timeUnixNano": str(now_nano + 128_000_000),
                                    "severityText": "ERROR",
                                    "body": {"stringValue": "Failed to connect to LDAP host ldap.corp.internal:636: timeout"},
                                    "traceId": "e1f2a3b4c5d6e7f80918273645546372",
                                    "spanId": "b2c3d4e5f6a10719",
                                }
                            ]
                        }
                    ],
                }
            ]
        }
        ev_traces = parse_otlp_traces(sample_traces)
        ev_logs = parse_otlp_logs(sample_logs)
        self.ingest(ev_traces, source="demo-otlp")
        self.ingest(ev_logs, source="demo-otlp")
        return {"ok": True, "traces_loaded": 2, "spans_loaded": len(ev_traces), "logs_loaded": len(ev_logs)}

    def get_status(self):
        with self.lock:
            self._recover()
            manifest = self.sealed_dir / "sealed-manifest.json"
            sealed = (
                json.loads(manifest.read_text())["segments"]
                if manifest.exists()
                else []
            )
            events = self.runtime.db.execute(
                "SELECT COUNT(*) FROM receipts"
            ).fetchone()[0]
            sealed_events = sum(s["count"] for s in sealed)
            ai_calls = self.runtime.db.execute(
                "SELECT COUNT(*) FROM receipts WHERE json_extract(event_json, '$.attributes.is_ai_call') = 1"
            ).fetchone()[0]
            return {
                "status": "online",
                "data_dir": str(self.data_dir),
                "total_ingested": events,
                "ai_calls": ai_calls,
                "wal_segments": sorted(
                    p.name for p in self.wal_dir.glob("wal-*.jsonl*")
                ),
                "wal_count": events - sealed_events,
                "sealed_segments": [s["name"] for s in sealed],
                "sealed_events": sealed_events,
                "traces": len(self.runtime.matching),
                "groups": len(self.runtime.groups.groups),
                "scoring_mode": self.runtime.scoring_mode,
                "sources": self.runtime.table("source_checkpoints"),
                "disk_bytes": sum(
                    p.stat().st_size for p in self.data_dir.rglob("*") if p.is_file()
                ),
                "paths": {
                    "wal": str(self.wal_dir),
                    "sealed": str(self.sealed_dir),
                    "index": str(self.index_dir),
                    "ledger": str(self.ledger_file),
                },
            }

    def close(self):
        with self.lock:
            if self._closed:
                return
            try:
                self._recover()
                self.wal_writer.close()
            finally:
                try:
                    self.wal_writer.abort()
                    self.runtime.close()
                finally:
                    self._writer_lock.close()
                    self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>snort telemetry store & search</title>
  <style>
    :root {
      --bg: #090d16;
      --card: #131b2e;
      --card-border: #1f2b48;
      --accent: #38bdf8;
      --accent-hover: #0284c7;
      --text: #f1f5f9;
      --muted: #94a3b8;
      --success: #10b981;
      --error: #ef4444;
      --ai: #a855f7;
      --code-bg: #0b1120;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
      padding: 24px;
      line-height: 1.5;
    }
    .container { max-width: 1300px; margin: 0 auto; }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 16px;
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand h1 { font-size: 24px; letter-spacing: -0.5px; color: var(--text); }
    .badge {
      background: rgba(16, 185, 129, 0.15);
      color: var(--success);
      border: 1px solid rgba(16, 185, 129, 0.3);
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 600;
    }
    .header-actions { display: flex; flex-wrap: wrap; gap: 8px; }
    button {
      background: var(--accent);
      color: #030712;
      border: none;
      padding: 8px 16px;
      border-radius: 6px;
      font-weight: 600;
      cursor: pointer;
      font-size: 13px;
      transition: background 0.15s;
    }
    button:hover { background: var(--accent-hover); }
    .btn-secondary { background: transparent; color: var(--text); border: 1px solid var(--card-border); }
    .btn-secondary:hover { background: var(--card-border); }
    .btn-compact { padding: 6px 12px; font-size: 12px; }

    /* Nav Tabs */
    .nav-tabs {
      display: flex;
      gap: 6px;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 20px;
      overflow-x: auto;
    }
    .tab-btn {
      background: transparent;
      color: var(--muted);
      border: none;
      border-bottom: 2px solid transparent;
      padding: 10px 18px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      border-radius: 6px 6px 0 0;
      white-space: nowrap;
      transition: all 0.15s;
    }
    .tab-btn:hover { color: var(--text); background: rgba(255, 255, 255, 0.02); }
    .tab-btn.active {
      color: var(--accent);
      border-bottom-color: var(--accent);
      background: rgba(56, 189, 248, 0.08);
    }
    .tab-content { display: none; }
    .tab-content.active { display: block; }

    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 220px), 1fr)); gap: 16px; margin-bottom: 24px; }
    .card {
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 18px;
    }
    .card-title { font-size: 12px; text-transform: uppercase; color: var(--muted); font-weight: 600; margin-bottom: 6px; }
    .card-val { font-size: 26px; font-weight: 700; color: var(--text); }
    .card-sub { font-size: 12px; color: var(--muted); margin-top: 4px; word-break: break-all; }

    .section { background: var(--card); border: 1px solid var(--card-border); border-radius: 10px; padding: 20px; margin-bottom: 20px; }
    .section-header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }
    h2 { font-size: 17px; font-weight: 600; color: var(--accent); }

    /* Waterfall Styles */
    .waterfall-layout {
      display: grid;
      grid-template-columns: 340px 1fr;
      gap: 18px;
      min-height: 520px;
    }
    .wf-sidebar {
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      display: flex;
      flex-direction: column;
      overflow: hidden;
      max-height: 720px;
    }
    .wf-sidebar-header {
      padding: 12px;
      border-bottom: 1px solid var(--card-border);
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .trace-list { overflow-y: auto; flex: 1; }
    .trace-item {
      padding: 12px 14px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      cursor: pointer;
      transition: background 0.15s;
    }
    .trace-item:hover { background: rgba(56, 189, 248, 0.06); }
    .trace-item.active { background: rgba(56, 189, 248, 0.14); border-left: 3px solid var(--accent); }
    .trace-item-title { font-weight: 600; font-size: 13px; color: var(--text); display: flex; justify-content: space-between; }
    .trace-item-meta { font-size: 11px; color: var(--muted); margin-top: 4px; display: flex; gap: 8px; flex-wrap: wrap; }

    .wf-main {
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 18px;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }
    .wf-main-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 12px;
    }
    .timeline-scale {
      display: flex;
      justify-content: space-between;
      font-size: 11px;
      color: var(--muted);
      border-bottom: 1px dashed var(--card-border);
      padding-bottom: 4px;
      margin-bottom: 8px;
    }
    .spans-container { overflow-y: auto; max-height: 400px; }
    .span-row {
      display: flex;
      align-items: center;
      padding: 6px 8px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
      margin-bottom: 3px;
      transition: background 0.1s;
    }
    .span-row:hover { background: rgba(255, 255, 255, 0.04); }
    .span-row.active { background: rgba(56, 189, 248, 0.12); }
    .span-label {
      width: 280px;
      min-width: 220px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .span-bar-lane {
      flex: 1;
      position: relative;
      height: 22px;
      background: rgba(255, 255, 255, 0.02);
      border-radius: 4px;
      margin-left: 12px;
    }
    .span-bar {
      position: absolute;
      top: 2px;
      height: 18px;
      border-radius: 3px;
      display: flex;
      align-items: center;
      padding: 0 6px;
      font-size: 10px;
      font-weight: 600;
      color: #fff;
      white-space: nowrap;
      overflow: hidden;
    }
    .span-bar.ok { background: #0284c7; }
    .span-bar.error { background: #dc2626; }
    .span-bar.ai { background: #9333ea; }
    .span-drawer {
      margin-top: 14px;
      padding-top: 12px;
      border-top: 1px solid var(--card-border);
      overflow-y: auto;
      max-height: 260px;
    }

    /* AI Call Table */
    table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 8px; }
    th { text-align: left; padding: 10px 12px; background: rgba(255,255,255,0.02); color: var(--muted); border-bottom: 1px solid var(--card-border); }
    td { padding: 9px 12px; border-bottom: 1px solid rgba(255,255,255,0.04); vertical-align: top; }
    tr:hover { background: rgba(56, 189, 248, 0.04); }
    .tag { padding: 2px 7px; border-radius: 4px; font-size: 11px; font-weight: 600; }
    .tag-ok { background: rgba(16, 185, 129, 0.2); color: var(--success); }
    .tag-err { background: rgba(239, 68, 68, 0.2); color: var(--error); }
    .tag-ai { background: rgba(168, 85, 247, 0.2); color: var(--ai); }
    .tag-service { background: rgba(56, 189, 248, 0.15); color: var(--accent); }

    /* Modal for AI Inspection */
    .modal-overlay {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.75);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 9999;
    }
    .modal-overlay.hidden { display: none; }
    .modal-box {
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      width: 90%;
      max-width: 840px;
      max-height: 85vh;
      overflow-y: auto;
      padding: 24px;
    }

    .drop-zone {
      border: 2px dashed var(--card-border);
      border-radius: 8px;
      padding: 26px;
      text-align: center;
      cursor: pointer;
      color: var(--muted);
      margin-bottom: 16px;
      transition: all 0.2s;
    }
    .drop-zone:hover { border-color: var(--accent); color: var(--text); }
    .code-box {
      background: var(--code-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 12px;
      font-size: 12px;
      overflow-x: auto;
      color: #e2e8f0;
      margin-bottom: 12px;
      white-space: pre-wrap;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    }
    .search-bar { display: flex; gap: 8px; margin-bottom: 12px; }
    input[type="text"], select {
      background: var(--code-bg);
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 13px;
      outline: none;
    }
    input[type="text"]:focus, select:focus { border-color: var(--accent); }
    .sql-editor {
      width: 100%;
      min-height: 100px;
      padding: 12px;
      background: var(--code-bg);
      border: 1px solid var(--card-border);
      color: var(--text);
      border-radius: 6px;
      font-family: monospace;
      font-size: 13px;
    }
    .result-box {
      background: var(--code-bg);
      border: 1px solid var(--card-border);
      border-radius: 6px;
      padding: 12px;
      color: var(--muted);
      font-size: 12px;
      max-height: 280px;
      overflow: auto;
      white-space: pre-wrap;
      margin-top: 8px;
    }
    @media (max-width: 900px) {
      .waterfall-layout { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <h1>snort</h1>
        <span class="badge">live engine online</span>
      </div>
      <div class="header-actions">
        <button class="btn-secondary" onclick="loadOtlpDemo()">load otlp + ai demo</button>
        <button class="btn-secondary" onclick="sealStore()">seal wal to lance</button>
      </div>
    </header>

    <div class="grid">
      <div class="card">
        <div class="card-title">events stored</div>
        <div class="card-val" id="stat-events">0</div>
        <div class="card-sub" id="stat-disk">disk: 0 kb</div>
      </div>
      <div class="card">
        <div class="card-title">traces assembled</div>
        <div class="card-val" id="stat-traces">0</div>
        <div class="card-sub" id="stat-wal">wal tail files: 0</div>
      </div>
      <div class="card">
        <div class="card-title">ai sdk calls</div>
        <div class="card-val" id="stat-ai-calls" style="color: var(--ai);">0</div>
        <div class="card-sub">prompt + completion tokens</div>
      </div>
      <div class="card">
        <div class="card-title">storage format</div>
        <div class="card-val" style="font-size: 18px;">lance + duckdb</div>
        <div class="card-sub">blake3 tamper verification</div>
      </div>
    </div>

    <!-- Navigation Tabs -->
    <div class="nav-tabs">
      <button class="tab-btn active" onclick="switchTab('overview')">Overview & Ingest</button>
      <button class="tab-btn" onclick="switchTab('waterfall')">Trace Waterfall</button>
      <button class="tab-btn" onclick="switchTab('ai')">AI Call Inspector</button>
      <button class="tab-btn" onclick="switchTab('search-sql')">Search & SQL Analytics</button>
    </div>

    <!-- TAB 1: OVERVIEW & INGEST -->
    <div id="tab-overview" class="tab-content active">
      <div class="section">
        <div class="section-header">
          <h2>network ingest sink & opentelemetry support</h2>
          <span style="font-size: 12px; color: var(--muted);">drop json/jsonl or point otlp exporters here</span>
        </div>
        <div class="drop-zone" id="drop-zone" onclick="document.getElementById('file-input').click()">
          drag and drop telemetry json/jsonl here to ingest immediately
          <input type="file" id="file-input" style="display:none" onchange="handleFileSelect(this.files)">
        </div>
        <p style="font-size: 13px; color: var(--muted); margin-bottom: 6px;">point your OpenTelemetry / Effect / LangChain app directly at snort:</p>
        <div class="code-box">
# OTLP HTTP Traces:
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT="http://127.0.0.1:8080/v1/traces"

# OTLP HTTP Logs:
export OTEL_EXPORTER_OTLP_LOGS_ENDPOINT="http://127.0.0.1:8080/v1/logs"

# Or standard JSON ingest via cURL:
curl -X POST http://127.0.0.1:8080/ingest \
  -H "Content-Type: application/json" \
  -d '{"ts": "2026-10-03T10:00:00Z", "host": "srv-1", "action": "exec", "raw": "powershell -enc 123"}'
        </div>
      </div>
    </div>

    <!-- TAB 2: TRACE WATERFALL -->
    <div id="tab-waterfall" class="tab-content">
      <div class="waterfall-layout">
        <!-- Left: Trace List -->
        <div class="wf-sidebar">
          <div class="wf-sidebar-header">
            <div style="font-size: 13px; font-weight: 600; color: var(--text);">Traces</div>
            <div style="display: flex; gap: 6px;">
              <input type="text" id="wf-filter" placeholder="filter by operation/service..." style="flex:1; padding: 6px 10px; font-size: 12px;" oninput="renderTraceList()">
              <button class="btn-compact btn-secondary" onclick="loadTraces()">refresh</button>
            </div>
          </div>
          <div class="trace-list" id="trace-list-items">
            <div style="padding: 16px; color: var(--muted); font-size: 12px;">loading traces...</div>
          </div>
        </div>

        <!-- Right: Trace Waterfall Viewer -->
        <div class="wf-main">
          <div class="wf-main-header">
            <div>
              <span id="wf-trace-title" style="font-size: 16px; font-weight: 700; color: var(--text);">Select a trace</span>
              <span id="wf-trace-badge" class="tag" style="margin-left: 8px;"></span>
              <div id="wf-trace-id" style="font-size: 11px; color: var(--muted); margin-top: 3px; font-family: monospace;"></div>
            </div>
            <div id="wf-trace-stats" style="font-size: 12px; color: var(--muted); text-align: right;"></div>
          </div>

          <div class="timeline-scale">
            <span>0ms</span>
            <span>25%</span>
            <span>50%</span>
            <span>75%</span>
            <span id="wf-total-duration">100%</span>
          </div>

          <div class="spans-container" id="spans-container">
            <div style="padding: 24px; text-align: center; color: var(--muted); font-size: 13px;">select a trace from the left panel to inspect the timeline waterfall.</div>
          </div>

          <!-- Span Detail Drawer -->
          <div class="span-drawer" id="span-drawer" style="display: none;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
              <h3 id="drawer-span-name" style="font-size: 14px; font-weight: 600; color: var(--accent);"></h3>
              <button class="btn-compact btn-secondary" onclick="document.getElementById('span-drawer').style.display='none'">close</button>
            </div>
            <pre id="drawer-span-json" class="code-box" style="max-height: 180px;"></pre>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 3: AI CALL INSPECTOR -->
    <div id="tab-ai" class="tab-content">
      <div class="section">
        <div class="section-header">
          <h2>ai call inspector (model, prompts, token counts)</h2>
          <div style="display: flex; gap: 8px;">
            <input type="text" id="ai-filter" placeholder="filter by model / service..." style="font-size: 12px; padding: 6px 10px;" oninput="renderAiTable()">
            <button class="btn-compact btn-secondary" onclick="loadAiCalls()">refresh</button>
          </div>
        </div>
        <div style="overflow-x: auto;">
          <table>
            <thead>
              <tr>
                <th>timestamp</th>
                <th>service</th>
                <th>model</th>
                <th>provider</th>
                <th>duration</th>
                <th>tokens (in / out)</th>
                <th>prompt preview</th>
                <th>action</th>
              </tr>
            </thead>
            <tbody id="ai-table-body">
              <tr><td colspan="8" style="text-align:center; color:var(--muted);">no AI calls detected yet.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 4: SEARCH & SQL -->
    <div id="tab-search-sql" class="tab-content">
      <div class="section">
        <div class="section-header">
          <h2>unified duckdb & lance bm25 search</h2>
        </div>
        <div class="search-bar">
          <input type="text" id="search-input" placeholder="search raw text across lance and unsealed wal..." onkeydown="if(event.key==='Enter') doSearch()" style="flex:1;">
          <button onclick="doSearch()">search</button>
        </div>
        <div style="display:flex; gap:16px; font-size:13px; color:var(--muted); margin-bottom:12px;">
          <label><input type="checkbox" id="bm25-toggle" checked> enable lance bm25 scoring</label>
          <label>filter: <input type="text" id="filter-input" placeholder="e.g. host = 'srv-1'" style="padding: 2px 6px; font-size: 12px;"></label>
        </div>
        <div id="search-results">
          <table id="results-table" style="display: none;">
            <thead>
              <tr><th style="width:70px;">source</th><th style="width:130px;">host</th><th style="width:110px;">action</th><th>raw telemetry</th><th style="width:70px;">score</th></tr>
            </thead>
            <tbody id="results-body"></tbody>
          </table>
          <div id="results-empty" style="color:var(--muted); font-size:13px; padding:8px 0;">enter a search query above.</div>
        </div>
      </div>

      <div class="section">
        <div class="section-header">
          <h2>read-only SQL analytics & groups</h2>
          <button class="btn-compact btn-secondary" onclick="loadGroups()">refresh groups</button>
        </div>
        <textarea id="sql-input" class="sql-editor" spellcheck="false">SELECT host, count(*) AS events FROM events GROUP BY host</textarea>
        <button class="btn-compact" style="margin-top:8px;" onclick="runSql()">run read-only SQL</button>
        <pre id="sql-results" class="result-box">query results will appear here.</pre>
        <pre id="group-results" class="result-box" style="margin-top:12px;">threat groups will appear here.</pre>
      </div>
    </div>

    <!-- AI Call Inspector Modal -->
    <div id="ai-modal" class="modal-overlay hidden" onclick="if(event.target===this) closeAiModal()">
      <div class="modal-box">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
          <div>
            <h3 id="modal-ai-title" style="font-size: 16px; font-weight: 700; color: var(--accent);">AI Call Detail</h3>
            <div id="modal-ai-sub" style="font-size: 12px; color: var(--muted); margin-top: 4px;"></div>
          </div>
          <button class="btn-compact btn-secondary" onclick="closeAiModal()">close</button>
        </div>
        <div style="margin-bottom: 12px;">
          <div style="font-size: 12px; font-weight: 600; color: var(--muted); margin-bottom: 4px;">Prompt</div>
          <pre id="modal-ai-prompt" class="code-box" style="max-height: 200px;"></pre>
        </div>
        <div style="margin-bottom: 12px;">
          <div style="font-size: 12px; font-weight: 600; color: var(--muted); margin-bottom: 4px;">Completion</div>
          <pre id="modal-ai-response" class="code-box" style="max-height: 200px;"></pre>
        </div>
        <div style="display: flex; justify-content: flex-end; gap: 8px;">
          <button id="modal-jump-btn" class="btn-compact" onclick="jumpToWaterfallFromModal()">Inspect Trace in Waterfall</button>
        </div>
      </div>
    </div>
  </div>

  <script>
    let currentTraces = [];
    let currentAiCalls = [];
    let selectedTraceId = null;
    let selectedAiTraceId = null;

    async function api(url, options) {
      const res = await fetch(url, options);
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || data.error || `HTTP ${res.status}`);
      return data;
    }

    function escapeHtml(value) {
      const el = document.createElement('span');
      el.textContent = String(value || '');
      return el.innerHTML;
    }

    function switchTab(name) {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      const activeBtn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.textContent.toLowerCase().includes(name.slice(0, 4)));
      if (activeBtn) activeBtn.classList.add('active');
      const content = document.getElementById(`tab-${name}`);
      if (content) content.classList.add('active');

      if (name === 'waterfall' && (!currentTraces || !currentTraces.length)) {
        loadTraces();
      } else if (name === 'ai' && (!currentAiCalls || !currentAiCalls.length)) {
        loadAiCalls();
      }
    }

    async function loadStatus() {
      try {
        const d = await api('/api/status');
        document.getElementById('stat-events').textContent = (d.total_ingested || 0).toLocaleString();
        document.getElementById('stat-traces').textContent = (d.traces || 0).toLocaleString();
        document.getElementById('stat-ai-calls').textContent = (d.ai_calls || 0).toLocaleString();
        document.getElementById('stat-wal').textContent = `wal files: ${(d.wal_segments || []).length}`;
        document.getElementById('stat-disk').textContent = `disk: ${(d.disk_bytes / 1024).toFixed(1)} kb`;
      } catch (e) {
        console.error('Status error:', e);
      }
    }

    async function loadTraces() {
      try {
        currentTraces = await api('/api/traces');
        renderTraceList();
        if (currentTraces && currentTraces.length && !selectedTraceId) {
          selectTrace(currentTraces[0].trace_id);
        }
      } catch (e) {
        console.error('Failed to load traces:', e);
      }
    }

    function renderTraceList() {
      const listEl = document.getElementById('trace-list-items');
      const filter = (document.getElementById('wf-filter').value || '').toLowerCase();
      listEl.innerHTML = '';

      const filtered = (currentTraces || []).filter(t =>
        !filter ||
        (t.root_operation && t.root_operation.toLowerCase().includes(filter)) ||
        (t.service && t.service.toLowerCase().includes(filter)) ||
        (t.trace_id && t.trace_id.toLowerCase().includes(filter))
      );

      if (!filtered.length) {
        listEl.innerHTML = '<div style="padding: 16px; color: var(--muted); font-size: 12px;">no matching traces</div>';
        return;
      }

      for (const t of filtered) {
        const item = document.createElement('div');
        item.className = `trace-item ${t.trace_id === selectedTraceId ? 'active' : ''}`;
        item.onclick = () => selectTrace(t.trace_id);
        const statusClass = t.status === 'error' ? 'tag-err' : 'tag-ok';
        item.innerHTML = `
          <div class="trace-item-title">
            <span>${escapeHtml(t.root_operation)}</span>
            <span class="tag ${statusClass}">${t.status.toUpperCase()}</span>
          </div>
          <div class="trace-item-meta">
            <span class="tag tag-service">${escapeHtml(t.service)}</span>
            <span>${t.duration_ms.toFixed(1)}ms</span>
            <span>${t.span_count} spans</span>
            ${t.ai_call_count ? '<span class="tag tag-ai">' + t.ai_call_count + ' AI</span>' : ''}
          </div>
        `;
        listEl.appendChild(item);
      }
    }

    async function selectTrace(traceId) {
      selectedTraceId = traceId;
      renderTraceList();
      try {
        const tree = await api(`/api/traces/${encodeURIComponent(traceId)}`);
        document.getElementById('wf-trace-title').textContent = tree.root_operation;
        document.getElementById('wf-trace-badge').textContent = tree.status.toUpperCase();
        document.getElementById('wf-trace-badge').className = `tag ${tree.status === 'error' ? 'tag-err' : 'tag-ok'}`;
        document.getElementById('wf-trace-id').textContent = `Trace ID: ${tree.trace_id}`;
        document.getElementById('wf-trace-stats').innerHTML = `
          <b>${tree.duration_ms.toFixed(2)} ms</b> &bull; ${tree.span_count} spans &bull; ${escapeHtml(tree.service)}
        `;
        document.getElementById('wf-total-duration').textContent = `${tree.duration_ms.toFixed(1)}ms`;

        const container = document.getElementById('spans-container');
        container.innerHTML = '';

        for (const s of tree.spans) {
          const row = document.createElement('div');
          row.className = 'span-row';
          row.onclick = () => showSpanDetail(s);

          const indent = Math.min(s.depth * 18, 160);
          const barColorClass = s.status === 'error' ? 'error' : (s.is_ai_call ? 'ai' : 'ok');
          const leftPct = s.offset_pct || 0;
          const widthPct = Math.max(s.width_pct || 1.5, 1.5);

          row.innerHTML = `
            <div class="span-label" style="padding-left: ${indent}px;" title="${escapeHtml(s.name)}">
              ${s.depth > 0 ? '<span style="color:var(--muted);">└─</span>' : ''}
              <span class="tag tag-service" style="font-size:10px; padding:1px 4px;">${escapeHtml(s.service)}</span>
              <span>${escapeHtml(s.name)}</span>
            </div>
            <div class="span-bar-lane">
              <div class="span-bar ${barColorClass}" style="left: ${leftPct}%; width: ${widthPct}%;">
                ${s.duration_ms.toFixed(1)}ms
              </div>
            </div>
          `;
          container.appendChild(row);
        }
      } catch (e) {
        console.error('Failed to load trace detail:', e);
      }
    }

    function showSpanDetail(span) {
      document.querySelectorAll('.span-row').forEach(r => r.classList.remove('active'));
      const drawer = document.getElementById('span-drawer');
      drawer.style.display = 'block';
      document.getElementById('drawer-span-name').textContent = `${span.service}: ${span.name} (${span.duration_ms.toFixed(2)}ms)`;
      document.getElementById('drawer-span-json').textContent = JSON.stringify({
        span_id: span.span_id,
        parent_span_id: span.parent_span_id || null,
        kind: span.kind,
        status: span.status,
        timestamp: span.ts,
        attributes: span.attributes,
        events: span.events,
        correlated_logs: span.logs
      }, null, 2);
    }

    async function loadAiCalls() {
      try {
        currentAiCalls = await api('/api/ai/calls');
        renderAiTable();
      } catch (e) {
        console.error('Failed to load AI calls:', e);
      }
    }

    function renderAiTable() {
      const tbody = document.getElementById('ai-table-body');
      const filter = (document.getElementById('ai-filter').value || '').toLowerCase();
      tbody.innerHTML = '';

      const filtered = (currentAiCalls || []).filter(c =>
        !filter ||
        (c.model && c.model.toLowerCase().includes(filter)) ||
        (c.service && c.service.toLowerCase().includes(filter)) ||
        (c.operation && c.operation.toLowerCase().includes(filter))
      );

      if (!filtered.length) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--muted);">no AI calls match filter</td></tr>';
        return;
      }

      filtered.forEach((c, idx) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td style="font-size:11px; color:var(--muted);">${escapeHtml(c.timestamp.slice(11, 19))}</td>
          <td><span class="tag tag-service">${escapeHtml(c.service)}</span></td>
          <td><b>${escapeHtml(c.model)}</b></td>
          <td>${escapeHtml(c.provider)}</td>
          <td>${c.duration_ms.toFixed(1)}ms</td>
          <td><code>${c.input_tokens} / ${c.output_tokens} (${c.total_tokens})</code></td>
          <td style="max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:var(--muted);">${escapeHtml(c.prompt_preview || '-')}</td>
          <td><button class="btn-compact btn-secondary" onclick="openAiModal(${idx})">Inspect</button></td>
        `;
        tbody.appendChild(tr);
      });
    }

    function openAiModal(idx) {
      const c = currentAiCalls[idx];
      if (!c) return;
      selectedAiTraceId = c.trace_id;
      document.getElementById('modal-ai-title').textContent = `${c.model} (${c.duration_ms.toFixed(1)}ms)`;
      document.getElementById('modal-ai-sub').textContent = `Service: ${c.service} &bull; Tokens: ${c.input_tokens} in, ${c.output_tokens} out (${c.total_tokens} total)`;
      document.getElementById('modal-ai-prompt').textContent = c.prompt || '(no prompt captured)';
      document.getElementById('modal-ai-response').textContent = c.completion || '(no completion captured)';
      document.getElementById('ai-modal').classList.remove('hidden');
    }

    function closeAiModal() {
      document.getElementById('ai-modal').classList.add('hidden');
    }

    function jumpToWaterfallFromModal() {
      closeAiModal();
      if (selectedAiTraceId) {
        switchTab('waterfall');
        selectTrace(selectedAiTraceId);
      }
    }

    async function loadOtlpDemo() {
      try {
        await api('/api/demo/otlp', { method: 'POST' });
        alert('Sample OTLP traces & AI calls loaded into Snort!');
        await loadStatus();
        await loadTraces();
        await loadAiCalls();
        switchTab('waterfall');
      } catch (e) {
        alert('Failed to load demo: ' + e.message);
      }
    }

    async function handleFileSelect(files) {
      if (!files || !files.length) return;
      for (const file of files) {
        const text = await file.text();
        await api('/ingest', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: text,
        });
      }
      alert('Ingestion complete!');
      await loadStatus();
      await loadTraces();
    }

    async function sealStore() {
      await api('/api/seal', { method: 'POST' });
      alert('WAL sealed to Lance dataset and indexed!');
      await loadStatus();
    }

    async function doSearch() {
      const q = document.getElementById('search-input').value.trim();
      if (!q) return;
      const bm25 = document.getElementById('bm25-toggle').checked;
      const filter = document.getElementById('filter-input').value.trim();
      const hits = await api(`/api/search?q=${encodeURIComponent(q)}&bm25=${bm25}${filter ? '&filter=' + encodeURIComponent(filter) : ''}`);
      const table = document.getElementById('results-table');
      const empty = document.getElementById('results-empty');
      const body = document.getElementById('results-body');
      body.innerHTML = '';
      if (!hits || !hits.length) {
        table.style.display = 'none';
        empty.style.display = 'block';
        empty.textContent = `no matches found for "${q}".`;
        return;
      }
      empty.style.display = 'none';
      table.style.display = 'table';
      for (const h of hits) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><span class="tag tag-service">${h._source || 'scan'}</span></td>
          <td>${escapeHtml(h.host || '-')}</td>
          <td>${escapeHtml(h.action || '-')}</td>
          <td style="word-break: break-all;"><pre style="margin:0; white-space:pre-wrap;">${escapeHtml(h.raw || '')}</pre></td>
          <td><code>${h._score ? h._score.toFixed(2) : '-'}</code></td>
        `;
        body.appendChild(tr);
      }
    }

    async function runSql() {
      const sql = document.getElementById('sql-input').value;
      const data = await api('/api/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sql })
      });
      document.getElementById('sql-results').textContent = JSON.stringify(data, null, 2);
    }

    async function loadGroups() {
      const groups = await api('/api/groups');
      document.getElementById('group-results').textContent = groups.length
        ? JSON.stringify(groups, null, 2)
        : 'no threat groups assembled yet.';
    }

    loadStatus();
    loadTraces();
    loadAiCalls();
    setInterval(loadStatus, 5000);
  </script>
</body>
</html>
"""


class SnortHttpHandler(BaseHTTPRequestHandler):
    store_manager: SnortStoreManager
    max_body_bytes = 64 * 1024 * 1024

    def log_message(self, format, *args):
        pass

    def _json(self, status, payload):
        body = json.dumps(payload, allow_nan=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _dispatch(self, function):
        try:
            function()
        except ConflictError as exc:
            self._json(
                409, {"ok": False, "error": "identity_conflict", "message": str(exc)}
            )
        except RequestError as exc:
            self._json(
                400, {"ok": False, "error": "invalid_request", "message": str(exc)}
            )
        except NotFoundError as exc:
            self._json(404, {"ok": False, "error": "not_found", "message": str(exc)})
        except Exception:
            logging.exception("snort request failed")
            self._json(
                500,
                {
                    "ok": False,
                    "error": "operation_failed",
                    "message": "Operation failed; see server log.",
                },
            )

    def do_GET(self):
        self._dispatch(self._get)

    def _integer(self, value):
        try:
            return int(value)
        except (TypeError, ValueError) as exc:
            raise RequestError("expected an integer") from exc

    def _payload(self, body):
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise RequestError("invalid JSON request") from exc

    def _get(self):
        parsed = urllib.parse.urlparse(self.path)
        path, params = parsed.path, urllib.parse.parse_qs(parsed.query)
        store = self.store_manager

        if path in ("/", "/index.html"):
            body = HTML_DASHBOARD.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/status":
            self._json(200, store.get_status())
        elif path == "/api/services":
            self._json(200, store.get_services())
        elif path in ("/api/traces", "/v1/traces"):
            if params.get("raw", ["false"])[0].lower() in ("true", "1"):
                limit = self._integer(params.get("limit", [100])[0])
                self._json(200, store.traces()[:limit])
            else:
                service = params.get("service", [None])[0]
                status = params.get("status", [None])[0]
                limit = self._integer(params.get("limit", [100])[0])
                self._json(
                    200,
                    store.get_traces_summary(
                        service=service, status=status, limit=limit
                    ),
                )
        elif path.startswith("/api/traces/") and len(path.split("/")) >= 4:
            trace_id = urllib.parse.unquote(path[len("/api/traces/") :])
            tree = store.get_trace_tree(trace_id)
            if tree is None:
                self._json(
                    404,
                    {
                        "ok": False,
                        "error": "trace_not_found",
                        "message": f"Trace {trace_id} not found",
                    },
                )
            else:
                self._json(200, tree)
        elif path.startswith("/api/spans/") and len(path.split("/")) >= 4:
            span_id = urllib.parse.unquote(path[len("/api/spans/") :])
            span = store.get_span(span_id)
            if span is None:
                self._json(
                    404,
                    {
                        "ok": False,
                        "error": "span_not_found",
                        "message": f"Span {span_id} not found",
                    },
                )
            else:
                self._json(200, span)
        elif path in ("/api/logs", "/v1/logs"):
            service = params.get("service", [None])[0]
            trace_id = params.get("trace_id", [None])[0]
            span_id = params.get("span_id", [None])[0]
            severity = params.get("severity", [None])[0]
            limit = self._integer(params.get("limit", [100])[0])
            self._json(
                200,
                store.get_logs(
                    service=service,
                    trace_id=trace_id,
                    span_id=span_id,
                    severity=severity,
                    limit=limit,
                ),
            )
        elif path == "/api/ai/calls":
            service = params.get("service", [None])[0]
            model = params.get("model", [None])[0]
            limit = self._integer(params.get("limit", [100])[0])
            self._json(
                200, store.get_ai_calls(limit=limit, service=service, model=model)
            )
        elif path == "/api/search":
            query = params.get("q", [""])[0]
            self._json(
                200,
                store.search_events(
                    query,
                    limit=self._integer(params.get("limit", [100])[0]),
                    bm25=params.get("bm25", ["false"])[0].lower()
                    in ("true", "1", "yes"),
                    filter_expr=params.get("filter", [None])[0],
                ),
            )
        elif path == "/api/query":
            self._json(
                200,
                store.query(
                    params.get("sql", [""])[0],
                    self._integer(params.get("limit", [1000])[0]),
                ),
            )
        elif path == "/api/groups":
            limit = self._integer(params.get("limit", [100])[0])
            if not 1 <= limit <= 10000:
                raise RequestError("limit must be between 1 and 10000")
            self._json(200, store.groups()[:limit])
        elif path.startswith("/api/groups/") and len(path.split("/")) == 4:
            self._json(200, store.groups(urllib.parse.unquote(path.split("/")[3])))
        elif path == "/api/sources":
            self._json(200, store.get_status()["sources"])
        elif path == "/api/ledger/verify":
            result = store.verify_ledger()
            self._json(200 if result["ok"] else 409, result)
        else:
            self._json(404, {"ok": False, "error": "not_found"})

    def do_POST(self):
        self._dispatch(self._post)

    def _post(self):
        path = urllib.parse.urlparse(self.path).path
        length = self._integer(self.headers.get("Content-Length", "0"))
        if length > self.max_body_bytes:
            self._json(413, {"ok": False, "error": "body_too_large"})
            return
        if length < 0:
            raise RequestError("Content-Length must be nonnegative")

        raw_bytes = self.rfile.read(length)
        if self.headers.get("Content-Encoding", "").lower() == "gzip":
            import gzip

            try:
                raw_bytes = gzip.decompress(raw_bytes)
            except Exception as exc:
                raise RequestError("invalid gzip payload") from exc

        try:
            body = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RequestError("body must be UTF-8") from exc

        if path in ("/v1/traces", "/api/v1/traces"):
            payload = self._payload(body)
            records = parse_otlp_traces(payload)
            result = self.store_manager.ingest(records, source="otlp-trace")
            self._json(
                200,
                {
                    "ok": True,
                    "insertedSpans": len(records),
                    "ingested": len(records),
                    "scoring_mode": result["scoring_mode"],
                },
            )
        elif path in ("/v1/logs", "/api/v1/logs"):
            payload = self._payload(body)
            records = parse_otlp_logs(payload)
            result = self.store_manager.ingest(records, source="otlp-log")
            self._json(
                200,
                {
                    "ok": True,
                    "insertedLogs": len(records),
                    "ingested": len(records),
                    "scoring_mode": result["scoring_mode"],
                },
            )
        elif path == "/api/demo/otlp":
            result = self.store_manager.demo_otlp()
            self._json(200, result)
        elif path in ("/ingest", "/api/ingest"):
            try:
                payload = json.loads(body)
                records = payload if isinstance(payload, list) else [payload]
            except json.JSONDecodeError:
                records = []
                for line_number, line in enumerate(body.splitlines(), 1):
                    if not line.strip():
                        continue
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError as exc:
                        raise RequestError(
                            f"invalid JSON on line {line_number}"
                        ) from exc
            self._json(
                200,
                self.store_manager.ingest(
                    records, request_key=self.headers.get("Idempotency-Key")
                ),
            )
        elif path == "/api/seal":
            self._json(200, self.store_manager.seal_and_index())
        elif path == "/api/query":
            payload = self._payload(body)
            if not isinstance(payload, dict) or "sql" not in payload:
                raise RequestError("query requires a sql field")
            self._json(
                200,
                self.store_manager.query(payload["sql"], payload.get("limit", 1000)),
            )
        elif path.startswith("/api/groups/") and path.endswith("/review"):
            payload = self._payload(body)
            if not isinstance(payload, dict) or not all(
                k in payload for k in ("trace_id", "decision")
            ):
                raise RequestError("review requires trace_id and decision")
            self._json(
                200,
                self.store_manager.review(
                    urllib.parse.unquote(path.split("/")[3]),
                    payload["trace_id"],
                    payload["decision"],
                ),
            )
        elif path == "/api/model/train":
            payload = self._payload(body)
            if not isinstance(payload, dict) or "pairs" not in payload:
                raise RequestError("training requires a pairs field")
            self._json(200, self.store_manager.train(payload["pairs"]))
        elif path == "/api/demo":
            records = [
                {
                    "ts": "2024-01-01T00:00:01Z",
                    "host": "web-1",
                    "action": "connect",
                    "raw": "nginx connection from 10.10.34.20",
                },
                {
                    "ts": "2024-01-01T00:01:00Z",
                    "host": "ws-2",
                    "action": "exec",
                    "raw": "powershell Invoke-Mimikatz dump credentials",
                },
            ]
            result = self.store_manager.ingest(records, source="dashboard-demo")
            self.store_manager.demo_otlp()
            self.store_manager.seal_and_index()
            self._json(200, result)
        else:
            self._json(404, {"ok": False, "error": "not_found"})


def run_server(
    data_dir: str | Path = "./snort_data",
    host: str = "127.0.0.1",
    port: int = 8080,
    open_browser: bool = False,
) -> None:
    store = SnortStoreManager(data_dir)

    class CustomHandler(SnortHttpHandler):
        store_manager = store

    server = ThreadingHTTPServer((host, port), CustomHandler)
    url = f"http://{host}:{server.server_port}"
    print(f"""
snort live telemetry engine online

[*] data directory : {store.data_dir}
[*] web dashboard  : {url}
[*] ingest endpoints:
    - OTLP Traces  : {url}/v1/traces (POST)
    - OTLP Logs    : {url}/v1/logs   (POST)
    - Raw JSON/L   : {url}/ingest    (POST)
[*] storage format : lance datasets + duckdb unified search

[press ctrl+c to stop]
""")
    if open_browser:
        import webbrowser

        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down snort server...")
    finally:
        server.server_close()
        store.close()
