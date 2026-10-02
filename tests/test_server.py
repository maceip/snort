"""Tests for the embedded snort HTTP server and network ingest sink."""

import json
import threading
import urllib.request
from snort.server import SnortStoreManager, SnortHttpHandler
from http.server import ThreadingHTTPServer


def test_server_ingest_and_search_endpoints(tmp_path):
    store = SnortStoreManager(tmp_path / "store")

    class TestHandler(SnortHttpHandler):
        store_manager = store

    server = ThreadingHTTPServer(("127.0.0.1", 0), TestHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"

    # 1. Test GET / (HTML dashboard)
    with urllib.request.urlopen(f"{base_url}/") as resp:
        assert resp.status == 200
        body = resp.read().decode("utf-8")
        assert "snort" in body
        assert "network ingest sink" in body

    # 2. Test GET /api/status
    with urllib.request.urlopen(f"{base_url}/api/status") as resp:
        assert resp.status == 200
        status = json.loads(resp.read().decode("utf-8"))
        assert status["status"] == "online"
        assert "wal" in status["paths"]

    # 3. Test POST /ingest
    test_events = [
        {
            "ts": "2024-01-01T12:00:00Z",
            "host": "web-srv",
            "action": "exec",
            "raw": "powershell -enc test1234",
        },
        {
            "ts": "2024-01-01T12:01:00Z",
            "host": "web-srv",
            "action": "connect",
            "raw": "nginx connect 10.10.10.1",
        },
    ]
    data = json.dumps(test_events).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}/ingest", data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        res = json.loads(resp.read().decode("utf-8"))
        assert res["ok"] is True
        assert res["ingested"] == 2

    # 4. Test live search on WAL tail
    with urllib.request.urlopen(f"{base_url}/api/search?q=powershell") as resp:
        assert resp.status == 200
        hits = json.loads(resp.read().decode("utf-8"))
        assert len(hits) == 1
        assert hits[0]["_source"] == "wal"
        assert "powershell" in hits[0]["raw"]

    # 5. Test POST /api/seal
    req = urllib.request.Request(
        f"{base_url}/api/seal", data=b"{}", headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        res = json.loads(resp.read().decode("utf-8"))
        assert len(res["sealed"]) >= 1

    # 6. Test search on sealed Lance dataset
    with urllib.request.urlopen(
        f"{base_url}/api/search?q=powershell&bm25=true"
    ) as resp:
        assert resp.status == 200
        hits = json.loads(resp.read().decode("utf-8"))
        assert len(hits) == 1
        assert hits[0]["_source"] == "index"
        assert hits[0]["_score"] > 0

    server.shutdown()
    server.server_close()
