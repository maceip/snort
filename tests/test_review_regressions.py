"""Regressions for the durable identity, ownership, and support review."""

import json
import sqlite3
import subprocess
import sys

import pytest

from snort.errors import ConflictError
from snort.group import GroupManager, ScoredLink
from snort.ingest.events import canonical_bytes, event_hash, hash_bytes, normalize_event
from snort.ingest.wal import WalWriter, verify_wal_chain
from snort.server import SnortStoreManager


def event(session="a", **extra):
    return dict(
        ts="2024-01-01T00:00:01Z",
        host="h",
        action="exec",
        raw="powershell credential dump 10.0.0.1",
        session_id=session,
        indicators={"ip": ["10.0.0.1"]},
        techniques=["T1003"],
        **extra,
    )


def test_shared_wal_rejects_second_writer_and_releases_after_close(tmp_path):
    wal = tmp_path / "shared-wal"
    alias = tmp_path / "wal-alias"
    with SnortStoreManager(tmp_path / "first", wal_dir=wal) as first:
        first.ingest([event()])
        alias.symlink_to(wal, target_is_directory=True)
        with pytest.raises(OSError):
            with SnortStoreManager(tmp_path / "second", wal_dir=alias):
                pytest.fail("second writer acquired the shared WAL")
        child = subprocess.run(
            [
                sys.executable,
                "-c",
                "from snort.server import SnortStoreManager\n"
                "import sys\n"
                "try:\n"
                "    store = SnortStoreManager(sys.argv[1], wal_dir=sys.argv[2])\n"
                "except OSError:\n"
                "    sys.exit(0)\n"
                "store.close()\n"
                "sys.exit(1)\n",
                str(tmp_path / "child"),
                str(wal),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert child.returncode == 0, child.stderr
        first.ingest([event("b")])
        assert verify_wal_chain(wal)["ok"]
    with SnortStoreManager(tmp_path / "second", wal_dir=wal) as second:
        assert second.get_status()["total_ingested"] == 2
        second.ingest([event("c")])
    assert verify_wal_chain(wal)["ok"]


def test_event_identity_is_independent_of_request_key_and_survives_restart(tmp_path):
    row = event(event_id="stable", source_id="agent")
    with SnortStoreManager(tmp_path) as store:
        assert store.ingest([row], request_key="one")["ingested"] == 1
        assert store.ingest([row], request_key="two")["duplicates"] == 1
        with pytest.raises(ConflictError):
            store.ingest([dict(row, raw="different content")], request_key="three")
        assert store.ingest([row])["duplicates"] == 1
        # Batch receipts remain independent even when all its events are duplicates.
        with pytest.raises(ConflictError):
            store.ingest([row, event("b")], request_key="two")
        assert store.get_status()["total_ingested"] == 1
    with SnortStoreManager(tmp_path) as store:
        assert store.ingest([row], request_key="four")["duplicates"] == 1
        with pytest.raises(ConflictError):
            store.ingest([dict(row, raw="different content")], request_key="five")
        assert store.verify_ledger()["ok"]


def test_event_ids_in_one_batch_deduplicate_without_losing_other_events(tmp_path):
    a = event(event_id="stable-a")
    b = event("b", event_id="stable-b")
    with SnortStoreManager(tmp_path) as store:
        result = store.ingest([a, a, b], request_key="batch")
        assert (result["ingested"], result["duplicates"]) == (2, 1)
        assert store.ingest([a, b], request_key="other")["duplicates"] == 2
        with pytest.raises(ConflictError):
            store.ingest([event("c"), dict(a, raw="changed")], request_key="conflict")
        assert store.get_status()["total_ingested"] == 2


def test_event_id_deduplication_cannot_bypass_sequence_conflicts(tmp_path):
    a = event(event_id="a", source_id="agent", source_seq=1)
    b = event("b", event_id="b", source_id="agent", source_seq=2)
    with SnortStoreManager(tmp_path) as store:
        store.ingest([a, b], request_key="first")
        with pytest.raises(ConflictError):
            store.ingest([dict(a, source_seq=2)], request_key="retry")
        with pytest.raises(ConflictError):
            store.ingest(
                [
                    event("c", event_id="c", source_id="agent", source_seq=3),
                    dict(a, source_seq=3),
                ],
                request_key="conflicting-batch",
            )
        assert store.get_status()["total_ingested"] == 2


def test_identity_upgrade_recognizes_previously_request_scoped_event_ids(tmp_path):
    row = event(event_id="stable", source_id="agent")
    with SnortStoreManager(tmp_path) as store:
        store.ingest([row], request_key="old-request")
    # Model an existing pre-fix projection, which has only the original receipts.
    with sqlite3.connect(tmp_path / "runtime.sqlite3") as db:
        db.execute("DROP TABLE IF EXISTS event_identities")
        db.execute("DROP TABLE IF EXISTS runtime_migrations")
    with SnortStoreManager(tmp_path) as store:
        assert store.ingest([row], request_key="new-request")["duplicates"] == 1
        with pytest.raises(ConflictError):
            store.ingest([dict(row, raw="changed")], request_key="changed-request")


def test_legacy_receipt_fingerprint_matches_retry_and_rejects_changed_content(tmp_path):
    row = event(source_id="agent", source_seq=7)
    with WalWriter(tmp_path / "wal") as writer:
        writer.append(normalize_event(row))
    with SnortStoreManager(tmp_path) as store:
        assert store.ingest([row])["duplicates"] == 1
        with pytest.raises(ConflictError):
            store.ingest([dict(row, raw="different")])
        assert store.get_status()["total_ingested"] == 1
    # Also repair legacy receipts that an older runtime already projected.
    with sqlite3.connect(tmp_path / "runtime.sqlite3") as db:
        db.execute("UPDATE receipts SET content_hash=event_hash")
        db.execute("DROP TABLE IF EXISTS runtime_migrations")
    with SnortStoreManager(tmp_path) as store:
        assert store.ingest([row], request_key="retry")["duplicates"] == 1
        assert store.verify_ledger()["ok"]


@pytest.mark.parametrize("request_scoped", [False, True])
def test_retry_of_event_normalized_at_reviewed_revision(tmp_path, request_scoped):
    row = event(
        source_id="agent",
        source_seq=7,
        event_id="legacy",
        template="powershell 10.0.0.1",
        object_class="process",
    )
    # Captured from normalize_event at 6bad1a8, before the newer enrichments.
    legacy = {
        "ts": "2024-01-01T00:00:01Z",
        "host": "h",
        "source_id": "agent",
        "source_seq": 7,
        "ingest_ts": "2024-01-01T00:00:02Z",
        "event_hash": "3fb8c1c7e1fa0b51ac28c10689f2c1278e8d4dd6ae2e289030060473baf80766",
        "template_hash": "b9e14e1bbc6ef35fbecd18f4760428d427bffafffc8ddf39a5d512d79451ebc2",
        "subject": "",
        "object": "",
        "action": "exec",
        "attributes": '{"event_id":"legacy","indicators":{"ip":["10.0.0.1"]},"session_id":"a","techniques":["T1003"]}',
        "raw": "powershell credential dump 10.0.0.1",
    }
    if request_scoped:
        fingerprint = hash_bytes(
            canonical_bytes(
                {
                    k: v
                    for k, v in legacy.items()
                    if k not in ("event_hash", "ingest_ts", "source_seq")
                }
            )
        )
        attrs = json.loads(legacy["attributes"])
        attrs["_snort_ingest"] = {
            "key": "request:agent:old:0",
            "content_hash": fingerprint,
        }
        legacy["attributes"] = canonical_bytes(attrs).decode()
        legacy["event_hash"] = event_hash(legacy)
    with WalWriter(tmp_path / "wal") as writer:
        writer.append(legacy)
    with SnortStoreManager(tmp_path) as store:
        assert store.ingest([row], request_key="new-key")["duplicates"] == 1
        for changed in (
            dict(row, raw="different"),
            dict(row, template="changed template"),
        ):
            with pytest.raises(ConflictError):
                store.ingest([changed], request_key="changed-key")
        assert store.verify_ledger()["ok"]
    with SnortStoreManager(tmp_path) as store:
        assert store.ingest([row], request_key="after-restart")["duplicates"] == 1
        assert store.runtime.db.execute(
            "SELECT event_hash FROM receipts"
        ).fetchall() == [(legacy["event_hash"],)]


@pytest.mark.parametrize("review", [None, "analyst-confirmed", "analyst-rejected"])
def test_live_support_refreshes_without_overwriting_analyst_decisions(tmp_path, review):
    tid = "session:h:a:0"
    with SnortStoreManager(tmp_path) as store:
        store.ingest([event(), event("b")])
        gid = store.groups()[0]["group_id"]
        if review:
            store.review(gid, tid, review)
        store.ingest(
            [
                dict(
                    event(),
                    ts="2024-01-01T00:00:02Z",
                    raw="unrelated",
                    tokens=[f"noise{i}" for i in range(200)],
                    indicators={},
                    techniques=[],
                )
            ]
        )
        member = store.groups(gid)["members"][tid]
        assert member["state"] == (review or "unsupported")
        if review != "analyst-rejected":
            assert member["strength"] < store.runtime.groups.tau_m
        assert (gid in store.runtime.groups.groups_of(tid)) == (
            review == "analyst-confirmed"
        )
        assert store.verify_ledger()["ok"]
    with SnortStoreManager(tmp_path) as store:
        assert store.groups(gid)["members"][tid]["state"] == (review or "unsupported")
        assert (gid in store.runtime.groups.groups_of(tid)) == (
            review == "analyst-confirmed"
        )


def test_old_links_cannot_keep_support_when_pair_is_no_longer_retrieved(
    tmp_path, monkeypatch
):
    from snort.retrieve.candidates import CandidateRetriever

    with SnortStoreManager(tmp_path) as store:
        store.ingest([event(), event("b")])
        gid = store.groups()[0]["group_id"]
        monkeypatch.setattr(CandidateRetriever, "retrieve", lambda self, trace: [])
        store.ingest([dict(event(), ts="2024-01-01T00:00:02Z", raw="changed")])
        members = store.groups(gid)["members"]
        assert all(m["state"] == "unsupported" for m in members.values())
        assert store.query("SELECT member_count FROM groups WHERE group_id='g1'") == [
            {"member_count": 0}
        ]


@pytest.mark.parametrize("review", [None, "analyst-confirmed", "analyst-rejected"])
def test_upgrade_repairs_saved_stale_support_and_retains_analyst_decisions(
    tmp_path, review
):
    tid = "session:h:a:0"
    with SnortStoreManager(tmp_path) as store:
        store.ingest([event(), event("b")])
        gid = store.groups()[0]["group_id"]
        if review:
            store.review(gid, tid, review)
        old_head = store.runtime.ledger.head()
    with sqlite3.connect(tmp_path / "runtime.sqlite3") as db:
        state = json.loads(
            db.execute("SELECT payload FROM state WHERE id=1").fetchone()[0]
        )
        # Pre-fix snapshots could save weakened links beside strong memberships.
        for link in state["links"]:
            link["score"] = 0.284
        db.execute("UPDATE state SET payload=? WHERE id=1", (json.dumps(state),))
        db.execute(
            "DELETE FROM runtime_migrations WHERE name='current-membership-support-v1'"
        )
    with SnortStoreManager(tmp_path) as store:
        member = store.groups(gid)["members"][tid]
        assert member["state"] == (review or "unsupported")
        if review != "analyst-rejected":
            assert member["strength"] == pytest.approx(0.284)
        assert store.query("SELECT member_count FROM groups WHERE group_id='g1'") == [
            {"member_count": int(review == "analyst-confirmed")}
        ]
        assert store.runtime.ledger.records[-1].kind == "membership-support-upgrade"
        assert store.runtime.ledger.records[-1].prev_hash == old_head
        assert store.verify_ledger()["ok"]
        repaired_head = store.runtime.ledger.head()
    with SnortStoreManager(tmp_path) as store:
        assert store.runtime.ledger.head() == repaired_head
        assert store.groups(gid)["members"][tid]["state"] == (review or "unsupported")


def test_support_demotes_reactivates_and_releases_membership_capacity():
    manager = GroupManager(max_memberships=1)
    gid = manager.maybe_seed("a", "b", 0.95, ("behavior", "infrastructure"))
    manager.assign("a", {gid: [ScoredLink("b", 0.9)]})
    assert manager.groups[gid].members["a"].state == "supported"
    manager.assign("a", {gid: [ScoredLink("b", 0.6)]})
    assert manager.groups[gid].members["a"].state == "proposed"
    manager.assign("a", {gid: [ScoredLink("b", 0.2)]})
    assert manager.groups_of("a") == []
    manager.assign("a", {gid: [ScoredLink("b", 0.9)]})
    assert manager.groups_of("a") == [gid]
    manager.assign("a", {gid: []})
    replacement = manager.maybe_seed("a", "c", 0.95, ("behavior", "infrastructure"))
    assert replacement is not None
    manager.assign("a", {gid: [ScoredLink("b", 0.9)]})
    assert manager.groups_of("a") == [replacement]
    with pytest.raises(ValueError):
        manager.analyst_decide("a", gid, "analyst-confirmed")


def test_sealing_benchmark_times_one_real_seal(monkeypatch):
    from scripts.bench_ingest import _events, _ingest_run

    sealed_counts = []
    original = SnortStoreManager.seal_and_index

    def observed(store):
        result = original(store)
        sealed_counts.append(result["sealed_count"])
        return result

    monkeypatch.setattr(SnortStoreManager, "seal_and_index", observed)
    report = _ingest_run(_events(8), 4)
    assert sealed_counts == [8]
    assert report["seal_events"] == 8
