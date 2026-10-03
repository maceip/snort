"""Subsystem 8: BLAKE3 Append-Only Decision Ledger & Cryptographic Verification."""

import os
from snort.ledger import Ledger


def test_ledger_subsystem_blake3_chain_and_tamper(tmp_path):
    """Verify hash chaining, raw segment records, multi-field verification, and tamper detection."""
    ledger = Ledger()

    # 1. Append raw segments and link decision records
    rec1 = ledger.append_segment(
        b"raw-telemetry-block-1", {"source": "sysmon", "host": "srv-1"}
    )
    assert rec1.kind == "segment"
    assert rec1.prev_hash == "0" * 64

    rec2 = ledger.append_segment(
        b"raw-telemetry-block-2", {"source": "auditd", "host": "srv-2"}
    )
    assert rec2.kind == "segment"
    assert rec2.prev_hash == rec1.record_hash

    rec3 = ledger.append(
        kind="links",
        inputs=[1, 2],
        model={"model": "logistic+isotonic", "version": 1},
        params={"budget": 20000, "threshold": 0.70},
        context={"round": 1},
        output=[{"trace_1": "t1", "trace_2": "t2", "p": 0.88}],
    )
    assert rec3.kind == "links"
    assert rec3.prev_hash == rec2.record_hash
    assert len(ledger) == 3

    # 2. Cryptographic verification on pristine ledger
    valid, errors = ledger.verify()
    assert valid is True
    assert errors == []

    # 3. Disk persistence & reload roundtrip
    ledger_path = os.path.join(str(tmp_path), "decision_ledger.jsonl")
    ledger.save(ledger_path)
    loaded_ledger = Ledger.load(ledger_path)
    assert len(loaded_ledger) == 3
    loaded_valid, loaded_errors = loaded_ledger.verify()
    assert loaded_valid is True
    assert loaded_errors == []

    # 4. Tamper Detection: Modified payload / metadata breaks hash chain
    tampered_ledger = Ledger.load(ledger_path)
    # Modify an attribute in the second record without updating hash
    tampered_ledger.records[1].context = {"source": "injected_adversary_context"}
    is_valid, tamper_errors = tampered_ledger.verify()
    assert is_valid is False
    assert len(tamper_errors) > 0

    # 5. Tail Truncation Check
    truncated_ledger = Ledger.load(ledger_path)
    truncated_ledger.records.pop()
    assert len(truncated_ledger) == 2
    trunc_valid, _ = truncated_ledger.verify()
    # Internal remaining records still chain correctly to each other
    assert trunc_valid is True
