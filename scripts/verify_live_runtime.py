"""Exercise the live HTTP pipeline across an abrupt process restart.

Run with .venv/bin/python scripts/verify_live_runtime.py. The store is temporary;
only the proof report is retained under bench/results/live-runtime/.
"""

import hashlib
import json
from pathlib import Path
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SERVER = """
import sys
from http.server import ThreadingHTTPServer
from snort.server import SnortStoreManager, SnortHttpHandler
store = SnortStoreManager(sys.argv[1])
class Handler(SnortHttpHandler):
    store_manager = store
server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
print(server.server_port, flush=True)
try:
    server.serve_forever()
except KeyboardInterrupt:
    pass
finally:
    server.server_close()
    store.close()
"""


def start(path):
    process = subprocess.Popen(
        [sys.executable, "-c", SERVER, str(path)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    port = process.stdout.readline().strip()
    if not port:
        raise RuntimeError(process.stderr.read())
    return process, f"http://127.0.0.1:{port}"


def request(url, path, data=None, expected=200):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(
        url + path, data=body, headers={"Content-Type": "application/json"}
    )
    try:
        response = urllib.request.urlopen(req, timeout=30)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        result = json.loads(response.read())
        assert response.status == expected, (path, response.status, result)
        return result


def record(seq, session, **extra):
    return dict(
        {
            "ts": f"2024-01-01T00:00:{seq + 1:02d}Z",
            "host": "ws-2",
            "source_id": "proof-agent",
            "source_seq": seq,
            "subject": session,
            "session_id": session,
            "action": "exec",
            "raw": "powershell credential dump 10.0.0.1",
            "indicators": {"ip": ["10.0.0.1"]},
            "techniques": ["T1003"],
        },
        **extra,
    )


def main():
    evidence = {}
    with TemporaryDirectory(prefix="snort-live-proof-") as temporary:
        process, url = start(temporary)
        try:
            rows = [
                record(0, "s1"),
                record(1, "s2"),
                record(
                    2,
                    "noise",
                    host="background",
                    raw="unrelated heartbeat",
                    indicators={},
                    techniques=[],
                ),
            ]
            assert request(url, "/ingest", rows)["ingested"] == 3
            assert len(request(url, "/api/search?q=powershell")) == 2
            groups = request(url, "/api/groups")
            assert groups
            gid = groups[0]["group_id"]
            members = list(groups[0]["members"])
            request(
                url,
                f"/api/groups/{gid}/review",
                {"trace_id": members[0], "decision": "analyst-confirmed"},
            )
            sql = "SELECT host,count(*) AS n FROM events GROUP BY host ORDER BY host"
            expected = [{"host": "background", "n": 1}, {"host": "ws-2", "n": 2}]
            assert request(url, "/api/query", {"sql": sql}) == expected
            assert request(url, "/ingest", rows)["duplicates"] == 3
            request(url, "/ingest", [record(0, "s1", raw="conflict")], expected=409)
            request(url, "/ingest", [{"host": "invalid"}], expected=400)
            request(url, "/api/query", {"sql": "DELETE FROM events"}, expected=400)
            request(
                url,
                "/api/query",
                {"sql": "SELECT * FROM read_csv('/etc/passwd')"},
                expected=400,
            )
            noise = next(
                t["trace_id"]
                for t in request(url, "/api/traces")
                if t["anchor"].endswith(":noise")
            )
            model = request(
                url,
                "/api/model/train",
                {
                    "pairs": [
                        {"a": members[0], "b": members[1], "match": 1},
                        {"a": members[0], "b": noise, "match": 0},
                    ]
                },
            )
            assert model["mode"] == "logistic-isotonic"
            request(url, "/api/seal", {})
            filtered = "/api/search?" + urllib.parse.urlencode(
                {"q": "powershell", "bm25": "true", "filter": "host = 'ws-2'"}
            )
            hits = request(url, filtered)
            assert len(hits) == 2 and all(h["_search_mode"] == "bm25" for h in hits)
            assert request(url, "/api/query", {"sql": sql}) == expected
            # Keep a durable, acknowledged event in an unmanifested open WAL.
            tail = record(3, "s4")
            assert request(url, "/ingest", [tail])["ingested"] == 1
            ledger_before = request(url, "/api/ledger/verify")
            assert ledger_before["ok"]
            process.kill()
            process.wait(timeout=10)
            process, url = start(temporary)
            assert request(url, "/api/status")["total_ingested"] == 4
            assert len(request(url, filtered)) == 3
            assert request(url, "/ingest", [tail])["duplicates"] == 1
            assert (
                request(url, f"/api/groups/{gid}")["members"][members[0]]["state"]
                == "analyst-confirmed"
            )
            assert request(url, "/api/status")["scoring_mode"] == "logistic-isotonic"
            assert request(url, "/api/sources") == [
                {"source_id": "proof-agent", "max_seq": 3}
            ]
            ledger_after = request(url, "/api/ledger/verify")
            assert ledger_after["ok"] and ledger_after["head"] == ledger_before["head"]
            evidence = {
                "ok": True,
                "events": 4,
                "groups": len(request(url, "/api/groups")),
                "native_bm25_hits_before_crash": len(hits),
                "filtered_hits_after_crash": 3,
                "scoring_mode": model["mode"],
                "ledger_records": ledger_after["records"],
                "ledger_head": ledger_after["head"],
                "abrupt_restart": "SIGKILL; acknowledged open WAL preserved",
                "checks": [
                    "live ingest/search/grouping",
                    "group review persistence",
                    "SQL aggregation",
                    "native BM25 filtering",
                    "idempotent retry",
                    "sequence conflict",
                    "invalid record errors",
                    "read-only/external-access SQL rejection",
                    "labeled pair training persistence",
                    "source checkpoint recovery",
                    "ledger verification across abrupt restart",
                ],
            }
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                process.communicate(timeout=15)
    digest = hashlib.sha256()
    for path in sorted((ROOT / "snort").rglob("*.py")):
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(path.read_bytes())
    evidence["source_sha256"] = digest.hexdigest()
    output = ROOT / "bench/results/live-runtime/report.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
