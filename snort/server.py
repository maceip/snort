"""Embedded single-process HTTP server and network ingest sink for snort."""

from __future__ import annotations

import json
import os
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from snort.errors import ConflictError, NotFoundError, RequestError

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
        from snort.store.search import query_tables
        from snort.runtime import snapshot_tables

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
            return {
                "status": "online",
                "data_dir": str(self.data_dir),
                "total_ingested": events,
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
    .container { max-width: 1200px; margin: 0 auto; }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 24px;
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
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card {
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 20px;
    }
    .card-title { font-size: 13px; text-transform: uppercase; color: var(--muted); font-weight: 600; margin-bottom: 8px; }
    .card-val { font-size: 28px; font-weight: 700; color: var(--text); }
    .card-sub { font-size: 12px; color: var(--muted); margin-top: 4px; word-break: break-all; }

    .section { background: var(--card); border: 1px solid var(--card-border); border-radius: 10px; padding: 24px; margin-bottom: 24px; }
    .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
    h2 { font-size: 18px; font-weight: 600; color: var(--accent); }

    .search-bar { display: flex; gap: 10px; margin-bottom: 16px; }
    input[type="text"] {
      flex: 1;
      background: var(--code-bg);
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 12px 16px;
      border-radius: 8px;
      font-size: 14px;
      outline: none;
    }
    input[type="text"]:focus { border-color: var(--accent); }
    button {
      background: var(--accent);
      color: #030712;
      border: none;
      padding: 12px 20px;
      border-radius: 8px;
      font-weight: 600;
      cursor: pointer;
      font-size: 14px;
      transition: background 0.15s;
    }
    button:hover { background: var(--accent-hover); }
    .btn-secondary { background: transparent; color: var(--text); border: 1px solid var(--card-border); }
    .btn-secondary:hover { background: var(--card-border); }

    .toggle-row { display: flex; align-items: center; gap: 20px; font-size: 13px; color: var(--muted); margin-bottom: 16px; }
    .toggle-row label { display: flex; align-items: center; gap: 6px; cursor: pointer; }

    pre, code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    .code-box {
      background: var(--code-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 14px;
      font-size: 13px;
      overflow-x: auto;
      color: #e2e8f0;
      margin-bottom: 12px;
    }

    table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 12px; }
    th { text-align: left; padding: 10px 12px; background: rgba(255,255,255,0.02); color: var(--muted); border-bottom: 1px solid var(--card-border); }
    td { padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,0.04); vertical-align: top; }
    tr:hover { background: rgba(56, 189, 248, 0.04); }
    .source-tag { padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; }
    .tag-index { background: rgba(56, 189, 248, 0.2); color: var(--accent); }
    .tag-scan { background: rgba(245, 158, 11, 0.2); color: #fbbf24; }
    .tag-wal { background: rgba(239, 68, 68, 0.2); color: #f87171; }
    .drop-zone {
      border: 2px dashed var(--card-border);
      border-radius: 8px;
      padding: 30px;
      text-align: center;
      cursor: pointer;
      color: var(--muted);
      margin-bottom: 16px;
      transition: all 0.2s;
    }
    .drop-zone:hover { border-color: var(--accent); color: var(--text); }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <h1>snort</h1>
        <span class="badge">live engine online</span>
      </div>
      <div>
        <button class="btn-secondary" onclick="sealStore()">seal wal to lance</button>
        <button class="btn-secondary" onclick="runDemo()">load demo sample</button>
      </div>
    </header>

    <div class="grid">
      <div class="card">
        <div class="card-title">events stored</div>
        <div class="card-val" id="stat-events">0</div>
        <div class="card-sub" id="stat-disk">disk: 0 kb</div>
      </div>
      <div class="card">
        <div class="card-title">lance segments</div>
        <div class="card-val" id="stat-segments">0</div>
        <div class="card-sub" id="stat-wal">wal tail files: 0</div>
      </div>
      <div class="card">
        <div class="card-title">storage engine</div>
        <div class="card-val" style="font-size: 20px;">lance + duckdb</div>
        <div class="card-sub">blake3 tamper verification</div>
      </div>
      <div class="card">
        <div class="card-title">data directory</div>
        <div class="card-val" style="font-size: 14px; word-break: break-all;" id="stat-path">loading...</div>
        <div class="card-sub">immutable data/ + unsealed wal</div>
      </div>
    </div>

    <!-- Network Sink Section -->
    <div class="section">
      <div class="section-header">
        <h2>network ingest sink</h2>
        <span style="font-size: 12px; color: var(--muted);">drop json/jsonl or stream over http</span>
      </div>
      <div class="drop-zone" id="drop-zone" onclick="document.getElementById('file-input').click()">
        drag and drop telemetry json/jsonl here to ingest immediately
        <input type="file" id="file-input" style="display:none" onchange="handleFileSelect(this.files)">
      </div>
      <p style="font-size: 13px; color: var(--muted); margin-bottom: 6px;">stream directly via curl:</p>
      <div class="code-box" id="curl-cmd">
curl -X POST http://localhost:8080/ingest \\
  -H "Content-Type: application/json" \\
  -d '{"ts": "2026-10-02T12:00:00Z", "host": "web-01", "action": "exec", "raw": "powershell whoami"}'
      </div>
    </div>

    <!-- Search Section -->
    <div class="section">
      <div class="section-header">
        <h2>unified duckdb & lance bm25 search</h2>
      </div>
      <div class="search-bar">
        <input type="text" id="search-input" placeholder="search raw text across lance and unsealed wal (e.g. powershell, 10.10.34, flag)..." onkeydown="if(event.key==='Enter') doSearch()">
        <button onclick="doSearch()">search</button>
      </div>
      <div class="toggle-row">
        <label><input type="checkbox" id="bm25-toggle" checked> enable lance bm25 relevance scoring</label>
        <label>filter: <input type="text" id="filter-input" placeholder="e.g. host = 'ws-2'" style="padding: 4px 8px; width: 220px; font-size: 12px; margin-left: 6px;"></label>
      </div>

      <div id="search-results">
        <table id="results-table" style="display: none;">
          <thead>
            <tr>
              <th style="width: 80px;">source</th>
              <th style="width: 140px;">host</th>
              <th style="width: 110px;">action</th>
              <th>raw telemetry</th>
              <th style="width: 80px;">score</th>
            </tr>
          </thead>
          <tbody id="results-body"></tbody>
        </table>
        <div id="results-empty" style="color: var(--muted); font-size: 13px; padding: 12px 0;">enter a query to search sealed lance segments and live wal tail.</div>
      </div>
    </div>
  </div>

  <div class="panel" style="margin: 24px;">
    <h2>live groups and SQL analytics</h2>
    <button onclick="loadGroups()">refresh groups</button>
    <pre id="group-results" style="white-space: pre-wrap;">load groups to inspect memberships and evidence.</pre>
    <textarea id="sql-input" style="width:100%;min-height:70px;">SELECT host, count(*) AS events FROM events GROUP BY host</textarea>
    <button onclick="runSql()">run read-only SQL</button>
    <pre id="sql-results" style="white-space: pre-wrap;"></pre>
    <div id="api-error" role="alert" style="color:#f88;"></div>
  </div>
  <script>
    async function api(url, options) {
      const res = await fetch(url, options);
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || data.error || `HTTP ${res.status}`);
      return data;
    }
    function escapeHtml(value) {
      const element = document.createElement('span');
      element.textContent = String(value);
      return element.innerHTML;
    }
    window.addEventListener('unhandledrejection', event => {
      document.getElementById('api-error').textContent = event.reason.message;
      event.preventDefault();
    });
    async function loadGroups() {
      document.getElementById('api-error').textContent = '';
      document.getElementById('group-results').textContent = JSON.stringify(await api('/api/groups'), null, 2);
    }
    async function runSql() {
      document.getElementById('api-error').textContent = '';
      const data = await api('/api/query', { method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({sql:document.getElementById('sql-input').value}) });
      document.getElementById('sql-results').textContent = JSON.stringify(data, null, 2);
    }
    async function loadStatus() {
      try {
        const d = await api('/api/status');
        document.getElementById('stat-events').textContent = (d.total_ingested || 0).toLocaleString();
        document.getElementById('stat-segments').textContent = (d.sealed_segments ? d.sealed_segments.length : 0);
        document.getElementById('stat-wal').textContent = `live wal events: ${d.wal_count || 0}`;
        document.getElementById('stat-disk').textContent = `disk: ${(d.disk_bytes / 1024).toFixed(1)} kb`;
        document.getElementById('stat-path').textContent = d.data_dir || '';
        document.getElementById('curl-cmd').textContent = `curl -X POST http://${window.location.host}/ingest \\\\n  -H "Content-Type: application/json" \\\\n  -d '{"ts": "${new Date().toISOString()}", "host": "srv-1", "action": "exec", "raw": "powershell -enc 123"}'`;
      } catch (e) {
        document.getElementById('api-error').textContent = e.message;
      }
    }

    async function doSearch() {
      const q = document.getElementById('search-input').value.trim();
      if (!q) return;
      const bm25 = document.getElementById('bm25-toggle').checked;
      const filter = document.getElementById('filter-input').value.trim();

      const url = `/api/search?q=${encodeURIComponent(q)}&bm25=${bm25}${filter ? '&filter=' + encodeURIComponent(filter) : ''}`;
      const hits = await api(url);

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
        const tagClass = h._source === 'index' ? 'tag-index' : h._source === 'wal' ? 'tag-wal' : 'tag-scan';
        const scoreStr = h._score ? h._score.toFixed(2) : '-';
        tr.innerHTML = `
          <td><span class="source-tag ${tagClass}">${h._source || 'scan'}</span></td>
          <td>${escapeHtml(h.host || '-')}</td>
          <td>${escapeHtml(h.action || '-')}</td>
          <td style="word-break: break-all;"><pre style="white-space: pre-wrap; margin:0;">${escapeHtml(h.raw || '')}</pre></td>
          <td><code>${scoreStr}</code></td>
        `;
        body.appendChild(tr);
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
      alert('ingestion complete!');
      await loadStatus();
      await doSearch();
    }

    async function sealStore() {
      await api('/api/seal', { method: 'POST' });
      alert('wal sealed to lance dataset and indexed!');
      await loadStatus();
    }

    async function runDemo() {
      await api('/api/demo', { method: 'POST' });
      alert('demo sample telemetry loaded and indexed!');
      await loadStatus();
      document.getElementById('search-input').value = 'powershell';
      await doSearch();
    }

    loadStatus();
    setInterval(loadStatus, 5000);
  </script>
</body>
</html>
"""


class SnortHttpHandler(BaseHTTPRequestHandler):
    store_manager: SnortStoreManager
    max_body_bytes = 16 * 1024 * 1024

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
            import logging

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
        elif path in ("/api/groups", "/api/traces"):
            limit = self._integer(params.get("limit", [100])[0])
            if not 1 <= limit <= 10000:
                raise RequestError("limit must be between 1 and 10000")
            self._json(
                200,
                (store.groups() if path.endswith("groups") else store.traces())[:limit],
            )
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
        try:
            body = self.rfile.read(length).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RequestError("body must be UTF-8") from exc
        if path in ("/ingest", "/api/ingest"):
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
[*] ingest endpoint: {url}/ingest (POST json or jsonl)
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
