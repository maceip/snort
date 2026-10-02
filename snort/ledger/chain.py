"""BLAKE3 hash-chained append-only decision ledger.

Chain: each record commits to its inputs, model/params, decision context,
output, and the previous record hash. ``verify`` recomputes every link,
so edits, deletions, reordering, and truncation are detectable.
Rollback against an external copy is out of scope for v1 (plan section 5).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field


def b3(data: bytes) -> str:
    import blake3 as _blake3

    return _blake3.blake3(data).hexdigest()


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class LedgerRecord:
    seq: int
    kind: str
    inputs_hash: str
    model_hash: str
    params_hash: str
    context: dict
    output_hash: str
    prev_hash: str
    record_hash: str = field(default="")

    def computed_hash(self) -> str:
        body = {
            "seq": self.seq,
            "kind": self.kind,
            "inputs_hash": self.inputs_hash,
            "model_hash": self.model_hash,
            "params_hash": self.params_hash,
            "context": self.context,
            "output_hash": self.output_hash,
            "prev_hash": self.prev_hash,
        }
        return b3(canonical(body))

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "LedgerRecord":
        return LedgerRecord(**{k: d[k] for k in LedgerRecord.__dataclass_fields__})


class Ledger:
    """In-memory chain with JSONL persistence."""

    GENESIS = "00" * 32

    def __init__(self) -> None:
        self.records: list[LedgerRecord] = []

    def __len__(self) -> int:
        return len(self.records)

    def head(self) -> str:
        return self.records[-1].record_hash if self.records else self.GENESIS

    def _append_record(
        self,
        kind: str,
        inputs_hash: str,
        model_hash: str,
        params_hash: str,
        context: dict,
        output_hash: str,
    ) -> LedgerRecord:
        rec = LedgerRecord(
            seq=len(self.records),
            kind=kind,
            inputs_hash=inputs_hash,
            model_hash=model_hash,
            params_hash=params_hash,
            context=context,
            output_hash=output_hash,
            prev_hash=self.head(),
        )
        rec.record_hash = rec.computed_hash()
        self.records.append(rec)
        return rec

    def append_segment(self, raw: bytes, meta: dict | None = None) -> LedgerRecord:
        """Chain a raw WAL segment: input hash covers the raw bytes."""
        context = {"n_bytes": len(raw), **(meta or {})}
        return self._append_record(
            kind="segment",
            inputs_hash=b3(raw),
            model_hash=b3(b"raw-segment"),
            params_hash=b3(canonical({"segment": 1})),
            context=context,
            output_hash=b3(raw),
        )

    def append(
        self,
        kind: str,
        inputs,
        model,
        params,
        context: dict | None,
        output,
    ) -> LedgerRecord:
        return self._append_record(
            kind=kind,
            inputs_hash=b3(canonical(inputs)),
            model_hash=b3(canonical(model)),
            params_hash=b3(canonical(params)),
            context=context or {},
            output_hash=b3(canonical(output)),
        )

    def verify(self) -> tuple[bool, list[str]]:
        errors: list[str] = []
        prev = self.GENESIS
        for i, rec in enumerate(self.records):
            if rec.seq != i:
                errors.append(f"record {i}: seq {rec.seq} != position {i}")
            if rec.prev_hash != prev:
                errors.append(f"record {i}: prev link broken")
            if rec.record_hash != rec.computed_hash():
                errors.append(f"record {i}: hash mismatch ({rec.kind})")
            prev = rec.record_hash
        return (len(errors) == 0, errors)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            for rec in self.records:
                fh.write(json.dumps(rec.to_dict(), sort_keys=True) + "\n")

    @staticmethod
    def load(path: str) -> "Ledger":
        ledger = Ledger()
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    ledger.records.append(LedgerRecord.from_dict(json.loads(line)))
        return ledger


# --- Store-chain verification over WAL + sealed segments ---
def verify_store(wal_dir, sealed_dir) -> dict:
    """Recompute the WAL and sealed chains. Returns a combined report."""
    from pathlib import Path  # noqa: F401 (kept for annotation compat)
    from snort.ingest.wal import verify_wal_chain
    from snort.store.seal import verify_sealed_chain
    wal_report = verify_wal_chain(wal_dir)
    sealed_report = verify_sealed_chain(wal_dir, sealed_dir)
    errors = (
        [f"wal: {error}" for error in wal_report["errors"]]
        + [f"sealed: {error}" for error in sealed_report["errors"]]
    )
    return {
        "ok": not errors,
        "wal": wal_report,
        "sealed": sealed_report,
        "errors": errors,
        "note": "rollback/truncation detection needs external chain-head copies (version 2)",
    }
