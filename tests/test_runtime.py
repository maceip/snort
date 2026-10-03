"""Subsystem 11: Live Runtime Orchestrator, Transactional SQLite Projection & State Replay."""

from snort.server import SnortStoreManager


def make_correlated_event(session="s1", **extra):
    return dict(
        {
            "ts": "2026-10-01T00:00:01Z",
            "host": "srv-prod",
            "subject": session,
            "session_id": session,
            "action": "exec",
            "raw": "powershell credential dump 10.0.0.1",
            "indicators": {"ip": ["10.0.0.1"]},
            "techniques": ["T1003"],
        },
        **extra,
    )


def test_runtime_subsystem_live_orchestration(tmp_path):
    """Verify live ingest, trace assembly, candidate scoring, overlapping grouping, ledger export, and restart recovery."""
    data_dir = tmp_path / "runtime_store"

    # 1. Initial live session with SnortStoreManager & LiveRuntime
    with SnortStoreManager(data_dir) as store:
        # Ingest two correlated events across sessions s1 and s2 sharing techniques & indicators
        res = store.ingest([make_correlated_event("s1"), make_correlated_event("s2")])
        assert res["ok"] is True
        assert res["ingested"] == 2
        assert res["duplicates"] == 0

        # Check total ingested status
        status = store.get_status()
        assert status["total_ingested"] == 2

        # Query transactional SQLite table snapshot
        sql = "SELECT e.host, count(*) AS n FROM events e JOIN trace_events t USING(event_hash) JOIN memberships m USING(trace_id) GROUP BY e.host"
        query_rows = store.query(sql)
        assert query_rows == [{"host": "srv-prod", "n": 2}]

        # Check group formation
        groups = store.groups()
        assert len(groups) >= 1
        gid = groups[0]["group_id"]
        group_detail = store.groups(gid)
        assert len(group_detail["members"]) == 2

        # Perform analyst review
        tid = next(iter(group_detail["members"].keys()))
        reviewed = store.review(gid, tid, "analyst-confirmed")
        assert reviewed["state"] == "analyst-confirmed"

        # Verify cryptographic decision ledger
        ledger_result = store.verify_ledger()
        assert ledger_result["ok"] is True

    # 2. Crash / Restart Recovery: Ensure state is completely preserved and replayed
    with SnortStoreManager(data_dir) as restarted:
        assert restarted.get_status()["total_ingested"] == 2
        # Analyst review state persisted
        assert restarted.groups(gid)["members"][tid]["state"] == "analyst-confirmed"
        # Duplicate detection on re-sent event
        dup_res = restarted.ingest([make_correlated_event("s1")])
        assert dup_res["duplicates"] == 1
        # Re-query transactional tables
        assert restarted.query(sql) == [{"host": "srv-prod", "n": 2}]
        # Ledger remains cryptographically valid after restart
        assert restarted.verify_ledger()["ok"] is True
