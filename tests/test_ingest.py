"""Focused checks for the version 1 ingest path: WAL, seal, index, search."""

import json
import subprocess
import sys
from pathlib import Path

import pyarrow.parquet as pq
import pytest

from snort.ingest.events import EVENT_COLUMNS, normalize_event
from snort.ingest.readers import iter_cta_json, iter_e3_jsonl
from snort.ingest.wal import WalReader, WalWriter, verify_wal_chain
from snort.ledger.chain import verify_store
from snort.store.index import build_index
from snort.store.search import search, split_query
from snort.store.seal import seal_segments

ROOT = Path(__file__).resolve().parents[1]

RAWS = [
    ("2024-01-01T00:00:01+00:00", "web-1", "nginx: connection from 10.10.34.20:72349 established"),
    ("2024-01-01T00:00:02+00:00", "web-1", "nginx: connection from 10.10.34.22:50010 closed"),
    ("2024-01-01T00:01:00+00:00", "ws-2", "powershell -enc SQBuAHYAbwBrAGUALQBMAG8AZwBnAGkAbgBnAA=="),
    ("2024-01-01T00:02:00+00:00", "web-1", "src: /10.10.34.22 sshd login failed for root"),
    ("2024-01-01T00:03:00+00:00", "web-1", "blk_1073746025 allocated 1073823744 bytes"),
    ("2024-01-01T00:04:00+00:00", "ws-2", "INFO heartbeat ok"),
    ("2024-01-01T00:04:01+00:00", "ws-2", "INFO heartbeat ok"),
]

QUERIES = [
    "10.10.34.20:72349",  # spans a variable boundary (ip:port)
    "src: /10.10.34.22",  # template text plus value
    "1073823744",  # exact variable
    "powershell",  # plain token
    "heartbeat",  # repeated line
    "missing-needle-xyz",  # no match
    "ok",  # shorter than the n-gram width: scan fallback
]


def _raw(ts, host, text, source="e3-cadets", seq=0):
    return {"ts": ts, "host": host, "action": "log", "object": text, "raw": text, "source_id": source, "source_seq": seq}


def _build_store(base: Path, *, index_first_only=True):
    wal_dir, sealed_dir, index_dir = base / "wal", base / "sealed", base / "index"
    with WalWriter(wal_dir, max_bytes=10**9) as wal:
        for i, (ts, host, text) in enumerate(RAWS[:4]):
            wal.append(normalize_event(_raw(ts, host, text, seq=i)))
        wal.roll()
        for i, (ts, host, text) in enumerate(RAWS[4:], start=4):
            wal.append(normalize_event(_raw(ts, host, text, seq=i)))
        wal.roll()
    sealed = seal_segments(wal_dir, sealed_dir, row_group_size=2)
    assert len(sealed) == 2
    if index_first_only:
        # Index only the first segment: the second stays unindexed so the
        # DuckDB scan path is exercised alongside the index path.
        first = sealed_dir / "sealed-manifest.json"
        manifest = json.loads(first.read_text())
        first.write_text(json.dumps({"segments": manifest["segments"][:1]}))
        indexed = build_index(sealed_dir, index_dir, backend="builtin")
        assert len(indexed) == 1
        first.write_text(json.dumps({"segments": manifest["segments"]}))
    else:
        indexed = build_index(sealed_dir, index_dir, backend="builtin")
        assert len(indexed) == 2
    return wal_dir, sealed_dir, index_dir


def _brute_force(query, sealed_dir, wal_dir):
    import lance
    expected = []
    manifest = sealed_dir / "sealed-manifest.json"
    sealed = json.loads(manifest.read_text())["segments"] if manifest.exists() else []
    for seg in sealed:
        ds = lance.dataset(str(sealed_dir / seg["name"]))
        table = ds.to_table(columns=["raw"])
        for row in range(table.num_rows):
            raw = str(table.column("raw")[row].as_py())
            if query in raw:
                expected.append(raw)
    return sorted(expected)


def test_template_hash_stable_event_hash_unique():
    first = normalize_event(_raw(*RAWS[0]))
    again = normalize_event(_raw(*RAWS[0]))
    assert first["event_hash"] == again["event_hash"]
    assert first["template_hash"] == again["template_hash"]
    other = normalize_event(_raw(*RAWS[0]) | {"source_seq": 99})
    assert other["event_hash"] != first["event_hash"]
    assert other["template_hash"] == first["template_hash"]
    with pytest.raises(ValueError):
        normalize_event({"host": "h", "action": "log"})


def test_readers_stamp_sequences(tmp_path):
    cta_path = tmp_path / "cta.json"
    cta_path.write_text(json.dumps([
        {"session_id": "s1", "actor": "a1", "host": "h1", "ts": "2024-01-01T00:00:00+00:00",
         "commands": [{"ts": "2024-01-01T00:00:00+00:00", "command": "whoami"},
                      "id -a"]},
    ]))
    cta_events = [normalize_event(r) for r in iter_cta_json(cta_path)]
    assert len(cta_events) == 2
    assert [e["source_seq"] for e in cta_events] == [0, 1]
    assert cta_events[0]["subject"] == "s1"

    e3_path = tmp_path / "e3.jsonl"
    e3_path.write_text('{"timestamp": "2024-01-01T00:00:00+00:00", "hostname": "h", "src": "p1", "dst": "f1", "event_type": "open"}\n')
    e3_events = [normalize_event(r) for r in iter_e3_jsonl(e3_path)]
    assert e3_events[0]["source_id"] == "e3-cadets"
    assert e3_events[0]["action"] == "open"


def test_wal_chain_and_tamper(tmp_path):
    wal_dir = tmp_path / "wal"
    with WalWriter(wal_dir, max_bytes=10**9) as wal:
        wal.append(normalize_event(_raw(*RAWS[0])))
        wal.roll()
    report = verify_wal_chain(wal_dir)
    assert report["ok"] and report["events"] == 1
    assert [e["event_hash"] for e in WalReader(wal_dir).iter_events()]

    segment = wal_dir / json.loads((wal_dir / "wal-manifest.json").read_text())["segments"][0]["name"]
    data = bytearray(segment.read_bytes())
    data[len(data) // 2] ^= 0xFF
    segment.write_bytes(bytes(data))
    assert not verify_wal_chain(wal_dir)["ok"]


def test_seal_writes_event_columns(tmp_path):
    import lance
    wal_dir, sealed_dir, _ = _build_store(tmp_path, index_first_only=False)
    for seg_file in sorted(sealed_dir.glob("seg-*.lance")):
        table = lance.dataset(str(sealed_dir / seg_file)).to_table()
        assert table.schema.names == EVENT_COLUMNS
    # Idempotent: sealing again seals nothing.
    assert seal_segments(wal_dir, sealed_dir) == []


def test_split_query_regions():
    assert split_query("10.10.34.20:72349") == ["10.10.34.20", "72349"]
    with pytest.raises(ValueError):
        split_query("   ")


def test_search_recall_matches_grep(tmp_path):
    wal_dir, sealed_dir, index_dir = _build_store(tmp_path, index_first_only=True)
    for query in QUERIES:
        found = search(query, sealed_dir, index_dir, wal_dir)
        assert sorted(m["raw"] for m in found) == _brute_force(query, sealed_dir, wal_dir), query
    indexed_hits = search("72349", sealed_dir, index_dir, wal_dir)
    assert indexed_hits and all(m["_source"] == "index" for m in indexed_hits)
    unindexed_hits = search("heartbeat", sealed_dir, index_dir, wal_dir)
    assert len(unindexed_hits) == 2 and all(m["_source"] == "scan" for m in unindexed_hits)


def test_search_scans_wal_tail(tmp_path):
    wal_dir = tmp_path / "wal"
    sealed_dir, index_dir = tmp_path / "sealed", tmp_path / "index"
    with WalWriter(wal_dir, max_bytes=10**9) as wal:
        wal.append(normalize_event(_raw(*RAWS[2])))
        # No roll: the event lives only in the unsealed WAL tail.
    found = search("powershell", sealed_dir, index_dir, wal_dir)
    assert len(found) == 1 and found[0]["_source"] == "wal"


def test_verify_store_and_tamper(tmp_path):
    wal_dir, sealed_dir, index_dir = _build_store(tmp_path, index_first_only=False)
    report = verify_store(wal_dir, sealed_dir)
    assert report["ok"], report["errors"]
    target = list((sealed_dir / "seg-000001.lance" / "data").glob("*.lance"))[0]
    data = bytearray(target.read_bytes())
    data[len(data) // 2] ^= 0xFF
    target.write_bytes(bytes(data))
    assert not verify_store(wal_dir, sealed_dir)["ok"]


def test_cli_demo_end_to_end():
    # demo-ingest is the ingest-level replay (plan section 4.1); the bare
    # `demo` command runs the full v1 demonstration (plan section 0).
    proc = subprocess.run(
        [sys.executable, "-m", "snort.cli", "demo-ingest"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assert report["verify"] is True
    assert report["searches"]["10.10.34.20:72349"] == 1
    assert report["searches"]["powershell"] == 1
