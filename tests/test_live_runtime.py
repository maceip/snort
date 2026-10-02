"""Regressions for all eight live ingest/query/grouping contracts."""

import json
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from snort.group import Group, GroupManager, Membership, ScoredLink
from snort.ingest.events import normalize_event
from snort.ingest.wal import WalReader, WalWriter, verify_wal_chain
from snort.server import SnortHttpHandler, SnortStoreManager


def event(session="s1", **extra):
    return dict(
        {
            "ts": "2024-01-01T00:00:01Z",
            "host": "ws-2",
            "subject": session,
            "session_id": session,
            "action": "exec",
            "raw": "powershell credential dump 10.0.0.1",
            "indicators": {"ip": ["10.0.0.1"]},
            "techniques": ["T1003"],
        },
        **extra,
    )


@pytest.fixture
def service(tmp_path):
    store = SnortStoreManager(tmp_path)

    class Handler(SnortHttpHandler):
        store_manager = store

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield store, f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()
    thread.join()
    store.close()


def request(url, path, data=None, headers=None):
    body = (
        data.encode()
        if isinstance(data, str)
        else json.dumps(data).encode()
        if data is not None
        else None
    )
    req = urllib.request.Request(
        url + path, data=body, headers=headers or {"Content-Type": "application/json"}
    )
    try:
        response = urllib.request.urlopen(req)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        return response.status, json.loads(response.read())


def test_http_real_ingest_group_query_review_and_restart(service, tmp_path):
    store, url = service
    status, result = request(url, "/ingest", [event("s1"), event("s2")])
    assert status == 200 and result["ingested"] == 2
    assert len(request(url, "/api/search?q=powershell")[1]) == 2
    groups = request(url, "/api/groups")[1]
    assert groups and len(groups[0]["members"]) == 2
    gid = groups[0]["group_id"]
    tid = next(iter(groups[0]["members"]))
    status, result = request(
        url,
        f"/api/groups/{gid}/review",
        {"trace_id": tid, "decision": "analyst-confirmed"},
    )
    assert status == 200 and result["state"] == "analyst-confirmed"
    assert request(url, f"/api/groups/{gid}")[1]["timeline"]
    sql = "SELECT e.host,count(*) AS n FROM events e JOIN trace_events t USING(event_hash) JOIN memberships m USING(trace_id) GROUP BY e.host"
    assert request(url, "/api/query", {"sql": sql}) == (200, [{"host": "ws-2", "n": 2}])
    assert request(url, "/api/ledger/verify")[1]["ok"]
    store.close()
    with SnortStoreManager(tmp_path) as restarted:
        assert restarted.get_status()["total_ingested"] == 2
        assert restarted.groups(gid)["members"][tid]["state"] == "analyst-confirmed"
        assert restarted.query(sql) == [{"host": "ws-2", "n": 2}]
        assert restarted.verify_ledger()["ok"]


def test_retry_sequences_checkpoints_and_conflicts(service):
    store, url = service
    rows = [event(source_id="agent-1", source_seq=42)]
    assert request(url, "/ingest", rows)[1]["ingested"] == 1
    assert request(url, "/ingest", rows)[1]["duplicates"] == 1
    assert request(url, "/api/sources")[1] == [{"source_id": "agent-1", "max_seq": 42}]
    assert (
        request(
            url, "/ingest", [event(source_id="agent-1", source_seq=42, raw="different")]
        )[0]
        == 409
    )
    assert store.get_status()["total_ingested"] == 1
    headers = {"Content-Type": "application/json", "Idempotency-Key": "request-1"}
    assert request(url, "/ingest", [event("s3")], headers)[0] == 200
    assert request(url, "/ingest", [event("s3")], headers)[1]["duplicates"] == 1
    assert request(url, "/ingest", [event("s3"), event("s4")], headers)[0] == 409


def test_orphan_and_partial_tail_recovery_never_overwrites(tmp_path):
    writer = WalWriter(tmp_path)
    writer.append(normalize_event(event()))
    tail = writer._path
    writer.abort()
    with tail.open("ab") as handle:
        handle.write(b'{"incomplete":')
    with WalWriter(tmp_path) as restarted:
        restarted.append(normalize_event(event("s2")))
    assert [e["subject"] for e in WalReader(tmp_path).iter_events()] == ["s1", "s2"]
    assert verify_wal_chain(tmp_path)["ok"]


def test_projection_failure_replays_durable_events(tmp_path, monkeypatch):
    store = SnortStoreManager(tmp_path)
    original = store.runtime.persist
    monkeypatch.setattr(
        store.runtime,
        "persist",
        lambda: (_ for _ in ()).throw(OSError("injected disk failure")),
    )
    with pytest.raises(OSError):
        store.ingest([event("s1"), event("s2")])
    assert store.runtime.db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 0
    monkeypatch.setattr(store.runtime, "persist", original)
    store.close()
    with SnortStoreManager(tmp_path) as restarted:
        assert restarted.get_status()["total_ingested"] == 2
        assert restarted.groups()
        assert restarted.ingest([event("s1"), event("s2")])["duplicates"] == 2
        assert restarted.verify_ledger()["ok"]


def test_global_membership_cap_seeding_assignment_and_review():
    manager = GroupManager()
    for i in range(8):
        manager.maybe_seed("shared", f"t{i}", 0.95, ("behavior", "infrastructure"))
    assert len(manager.groups_of("shared")) == 3
    for i in range(8):
        gid = f"extra-{i}"
        manager.groups[gid] = Group(gid, {f"m{i}": Membership(f"m{i}", gid, 0.9)})
        manager.assign("shared", {gid: [ScoredLink(f"m{i}", 0.95)]})
    assert len(manager.groups_of("shared")) == 3
    gid = manager.groups_of("shared")[0]
    manager.analyst_decide("shared", gid, "analyst-rejected")
    manager.maybe_seed("shared", "replacement", 0.95, ("behavior", "infrastructure"))
    assert len(manager.groups_of("shared")) == 3
    with pytest.raises(ValueError):
        manager.analyst_decide("shared", gid, "analyst-confirmed")


def test_filters_match_live_sealed_bm25_and_unindexed(service):
    store, url = service
    request(url, "/ingest", [event("s1"), event("s2", host="other-host")])
    for bm25 in (False, True):
        hits = store.search_events(
            "powershell", bm25=bm25, filter_expr="host = 'ws-2' AND ts >= '2024-01-01'"
        )
        assert len(hits) == 1 and hits[0]["host"] == "ws-2"
    # Seal without indexing: explicit substring fallback still applies the filter.
    store.wal_writer.roll()
    from snort.store.seal import seal_segments

    seal_segments(store.wal_dir, store.sealed_dir)
    hits = store.search_events("powershell", bm25=True, filter_expr="host = 'ws-2'")
    assert len(hits) == 1 and hits[0]["_search_mode"] == "substring-fallback"
    store.seal_and_index()
    store.ingest([event("s3", host="other-host")])
    assert all(
        h["host"] == "ws-2"
        for h in store.search_events(
            "powershell", bm25=True, filter_expr="host = 'ws-2'"
        )
    )
    assert request(url, "/api/search?q=powershell&filter=unknown_field%3D1")[0] == 400


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM events",
        "SELECT 1; SELECT 2",
        "SELECT * FROM read_csv('/etc/passwd')",
        "INSTALL httpfs",
    ],
)
def test_read_only_sql_rejects_writes_and_external_access(service, sql):
    store, url = service
    assert request(url, "/api/query", {"sql": sql})[0] == 400
    assert store.get_status()["total_ingested"] == 0


def test_invalid_batch_is_atomic_and_failures_are_visible(service, monkeypatch):
    store, url = service
    assert request(url, "/ingest", [event(), {"host": "bad"}])[0] == 400
    assert request(url, "/ingest", '{"bad-json"')[0] == 400
    assert request(url, "/api/query", {})[0] == 400
    assert store.get_status()["total_ingested"] == 0
    monkeypatch.setattr(
        store,
        "search_events",
        lambda *a, **k: (_ for _ in ()).throw(OSError("disk unavailable")),
    )
    status, result = request(url, "/api/search?q=hello")
    assert status == 500 and result["ok"] is False
    monkeypatch.setattr(
        store.wal_writer,
        "append",
        lambda *a: (_ for _ in ()).throw(OSError("disk full")),
    )
    assert request(url, "/ingest", [event()])[0] == 500


def test_index_creation_error_is_not_swallowed(tmp_path, monkeypatch):
    import lance

    with SnortStoreManager(tmp_path) as store:
        store.ingest([event()])
        store.wal_writer.roll()
        from snort.store.seal import seal_segments

        seal_segments(store.wal_dir, store.sealed_dir)

        def fail(*args, **kwargs):
            raise OSError("index disk full")

        monkeypatch.setattr(lance.LanceDataset, "create_scalar_index", fail)
        with pytest.raises(OSError, match="index disk full"):
            store.seal_and_index()
        assert not (store.index_dir / "index-manifest.json").exists()


def test_model_training_persists_and_audits_supplied_labels(tmp_path):
    with SnortStoreManager(tmp_path) as store:
        store.ingest([event("s1"), event("s2"), event("s3", raw="unrelated heartbeat")])
        tids = list(store.runtime.matching)
        result = store.train(
            [
                {"a": tids[0], "b": tids[1], "match": 1},
                {"a": tids[0], "b": tids[2], "match": 0},
            ]
        )
        assert result["mode"] == "logistic-isotonic"
        before = store.runtime.model.predict_proba([[1] * 8]).tolist()
        assert store.verify_ledger()["ok"]
    with SnortStoreManager(tmp_path) as store:
        assert store.runtime.scoring_mode == "logistic-isotonic"
        assert store.runtime.model.predict_proba([[1] * 8]).tolist() == before
        assert any(r.kind == "model-training" for r in store.runtime.ledger.records)


def test_cli_ingest_resume_and_group_analytics(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in [event("s1"), event("s2")]))
    data = tmp_path / "store"
    cmd = [
        sys.executable,
        "-m",
        "snort.cli",
        "ingest",
        str(path),
        "--data-dir",
        str(data),
    ]
    first = subprocess.run(cmd, text=True, capture_output=True, check=True)
    again = subprocess.run(cmd, text=True, capture_output=True, check=True)
    assert json.loads(first.stdout)["ingested"] == 2
    assert json.loads(again.stdout)["duplicates"] == 2
    query = subprocess.run(
        [
            sys.executable,
            "-m",
            "snort.cli",
            "query",
            "SELECT COUNT(*) AS n FROM groups",
            "--data-dir",
            str(data),
        ],
        text=True,
        capture_output=True,
        check=True,
    )
    assert json.loads(query.stdout)[0]["n"] >= 1


def test_wal_failed_fsync_requires_recovery_and_preserves_complete_record(
    tmp_path, monkeypatch
):
    import snort.ingest.wal as module

    writer = WalWriter(tmp_path)
    writer.append(normalize_event(event("s1")))
    original = module.os.fsync
    monkeypatch.setattr(
        module.os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("fsync failure"))
    )
    with pytest.raises(OSError):
        writer.append(normalize_event(event("s2")))
    with pytest.raises(RuntimeError, match="requires recovery"):
        writer.append(normalize_event(event("s3")))
    monkeypatch.setattr(module.os, "fsync", original)
    writer.abort()
    with WalWriter(tmp_path):
        pass
    assert len(list(WalReader(tmp_path).iter_events())) == 2
    assert verify_wal_chain(tmp_path)["ok"]


def test_corrupt_orphan_is_refused_without_overwrite(tmp_path):
    writer = WalWriter(tmp_path)
    writer.append(normalize_event(event()))
    path = writer._path
    writer.abort()
    changed = path.read_bytes().replace(b"powershell", b"corruption", 1)
    path.write_bytes(changed)
    with pytest.raises(ValueError, match="corrupt orphan"):
        WalWriter(tmp_path)
    assert path.read_bytes() == changed


def test_explicit_extension_fallback_keeps_filters(tmp_path, monkeypatch):
    import duckdb
    import importlib

    module = importlib.import_module("snort.store.search")
    with SnortStoreManager(tmp_path) as store:
        store.ingest([event("s1"), event("s2", host="other-host")])
        store.seal_and_index()
        monkeypatch.setattr(
            module,
            "_duckdb_con",
            lambda: (_ for _ in ()).throw(duckdb.Error("extension unavailable")),
        )
        hits = store.search_events("powershell", filter_expr="host = 'ws-2'")
        assert len(hits) == 1 and hits[0]["_search_mode"] == "arrow-substring-fallback"


def test_concurrent_ingest_query_and_seal_keep_receipts_consistent(service):
    from concurrent.futures import ThreadPoolExecutor

    store, url = service

    def work(i):
        result = request(
            url, "/ingest", [event(f"s{i}", source_id="parallel", source_seq=i)]
        )
        assert result[0] == 200
        assert (
            request(url, "/api/query", {"sql": "SELECT count(*) AS n FROM events"})[0]
            == 200
        )
        if i % 3 == 0:
            assert request(url, "/api/seal", {})[0] == 200

    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(work, range(9)))
    assert store.get_status()["total_ingested"] == 9
    assert store.query("SELECT count(*) AS n FROM events") == [{"n": 9}]
    assert all(
        len(store.runtime.groups.groups_of(t)) <= 3 for t in store.runtime.matching
    )
    assert store.verify_ledger()["ok"]


def test_cli_can_ingest_and_query_a_running_service(service, tmp_path):
    store, url = service
    path = tmp_path / "live.jsonl"
    path.write_text(json.dumps(event("via-cli")) + "\n")
    command = [
        sys.executable,
        "-m",
        "snort.cli",
        "ingest",
        str(path),
        "--server",
        url,
        "--source-id",
        "cli-agent",
    ]
    result = subprocess.run(command, text=True, capture_output=True, check=True)
    assert json.loads(result.stdout)["ingested"] == 1
    query = subprocess.run(
        [
            sys.executable,
            "-m",
            "snort.cli",
            "query",
            "SELECT count(*) AS n FROM events",
            "--data-dir",
            str(tmp_path),
        ],
        text=True,
        capture_output=True,
        check=True,
    )
    assert json.loads(query.stdout) == [{"n": 1}]


def test_internal_json_failure_is_500_and_client_parse_failure_is_400(
    service, monkeypatch
):
    store, url = service
    assert request(url, "/api/search?q=hello&limit=invalid")[0] == 400
    assert request(url, "/api/model/train", '{"invalid"')[0] == 400
    assert request(url, "/api/groups/absent")[0] == 404

    def fail():
        raise json.JSONDecodeError("corrupt stored manifest", "{", 0)

    monkeypatch.setattr(store, "get_status", fail)
    assert request(url, "/api/status")[0] == 500


def test_failed_ledger_export_recovers_committed_review(service, monkeypatch):
    store, url = service
    store.ingest([event("s1"), event("s2")])
    group = store.groups()[0]
    tid = next(iter(group["members"]))
    export = store.runtime.export_ledger
    monkeypatch.setattr(
        store.runtime,
        "export_ledger",
        lambda: (_ for _ in ()).throw(OSError("export disk full")),
    )
    assert (
        request(
            url,
            f"/api/groups/{group['group_id']}/review",
            {"trace_id": tid, "decision": "analyst-confirmed"},
        )[0]
        == 500
    )
    monkeypatch.setattr(store.runtime, "export_ledger", export)
    assert request(url, "/api/ledger/verify")[1]["ok"]
    assert (
        store.groups(group["group_id"])["members"][tid]["state"] == "analyst-confirmed"
    )


def test_time_range_filters_and_sql_types_are_consistent(service):
    store, url = service
    store.ingest(
        [
            event("s1", ts="2024-01-01T00:00:01Z"),
            event("s2", ts="2023-12-31T19:00:01-05:00"),
        ]
    )
    predicate = "ts >= '2024-01-01T00:00:01Z' AND ts < '2024-01-01T00:00:02Z'"
    for sealed in (False, True):
        if sealed:
            store.seal_and_index()
        for bm25 in (False, True):
            assert (
                len(store.search_events("powershell", bm25=bm25, filter_expr=predicate))
                == 2
            )
    result = request(
        url,
        "/api/query",
        {
            "sql": "SELECT ts,CAST(1.25 AS DECIMAL(4,2)) AS amount FROM events ORDER BY ts"
        },
    )
    assert result == (200, [{"ts": "2024-01-01T00:00:01+00:00", "amount": "1.25"}] * 2)


def test_nonfinite_input_is_rejected_before_writing(service):
    store, url = service
    assert request(url, "/ingest", [event(attributes={"bad": float("nan")})])[0] == 400
    assert store.get_status()["total_ingested"] == 0


def test_attributes_cannot_replace_stored_event_identity(service):
    store, url = service
    result = store.ingest(
        [
            event(
                attributes={
                    "host": "spoof",
                    "event_hash": "spoof",
                    "raw": "overridden",
                    "source_seq": 999,
                }
            )
        ]
    )
    trace = store.traces()[0]
    assert trace["anchor"] == "session:ws-2:s1"
    assert trace["member_event_hashes"] == result["event_hashes"]
    assert store.query(
        "SELECT count(*) AS n FROM events JOIN trace_events USING(event_hash)"
    ) == [{"n": 1}]


def test_missing_manifested_wal_fails_search_and_seal(service):
    store, url = service
    store.ingest([event()])
    entry = store.wal_writer.roll()
    path = store.wal_dir / entry["name"]
    original = path.read_bytes()
    path.unlink()
    try:
        assert request(url, "/api/search?q=powershell")[0] == 500
        assert request(url, "/api/seal", {})[0] == 500
    finally:
        path.write_bytes(original)
