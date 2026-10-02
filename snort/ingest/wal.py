"""Hash-chained append-only WAL segments (plan sections 3 and 4.1).

Layout: ``<wal_dir>/wal-<seq:06d>.jsonl``, one JSON envelope per line.
Legacy compressed ``.jsonl.zst`` segments remain readable:

    {"source_id", "source_seq", "ingest_ts", "event": {...},
     "prev": <prev record hash or segment's prev root>,
     "record_hash": blake3(prev + canonical event bytes)}

``record_hash`` chains every record to its predecessor; each segment
footer chains to the previous segment's root, so ``wal-manifest.json``
holds one tamper-evident chain over all raw bytes. No event is lost once
appended: writers flush and fsync before returning.
"""

from __future__ import annotations

import io
import json
import os
import time
from pathlib import Path

from snort.ingest.events import canonical_bytes, hash_bytes
from snort.persistence import atomic_write, sync_directory

MANIFEST_NAME = "wal-manifest.json"
DEFAULT_MAX_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_AGE_S = 3600

try:
    import zstandard as _zstd

    _ZSTD = True
except ImportError:  # pragma: no cover - environment without zstandard
    _ZSTD = False


def _open_compressed(path: Path, mode: str):
    """Open a segment file for binary I/O (zstd when available)."""
    if path.suffix == ".zst":
        if not _ZSTD:
            raise RuntimeError(f"cannot use {path}: zstandard is not installed")
        if "w" in mode:
            fh = open(path, "wb")
            ctx = _zstd.ZstdCompressor(level=3)
            return ctx.stream_writer(fh, closefd=True)
        fh = open(path, "rb")
        ctx = _zstd.ZstdDecompressor()
        return ctx.stream_reader(fh, closefd=True)
    return open(path, "wb" if "w" in mode else "rb")


def _read_lines(path: Path):
    if path.suffix == ".zst":
        with _open_compressed(path, "rb") as fh:
            yield from io.TextIOWrapper(fh, encoding="utf-8")
    else:
        with open(path, "r", encoding="utf-8") as fh:
            yield from fh


def _segment_name(seq: int) -> str:
    # Incremental JSONL makes each fsynced record independently recoverable.
    # Legacy compressed segments remain readable through _read_lines.
    return f"wal-{seq:06d}.jsonl"


def record_hash(prev: str, event: dict) -> str:
    return hash_bytes(prev.encode("utf-8") + b"|" + canonical_bytes(event))


class WalWriter:
    """Append normalized events to hash-chained WAL segments."""

    def __init__(
        self,
        wal_dir: str | Path,
        *,
        max_bytes: int = DEFAULT_MAX_BYTES,
        max_age_s: float = DEFAULT_MAX_AGE_S,
    ) -> None:
        self.dir = Path(wal_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.max_age_s = max_age_s
        self.manifest_path = self.dir / MANIFEST_NAME
        self.segments: list[dict] = self._load_manifest()
        self._recover_orphans()
        self._fh = None
        self._path: Path | None = None
        self._seq = max((s["seq"] for s in self.segments), default=0)
        self._count = 0
        self._bytes = 0
        self._prev = self.segments[-1]["root"] if self.segments else "GENESIS"
        self._opened_at = 0.0
        self._failed = False

    def _load_manifest(self) -> list[dict]:
        if not self.manifest_path.exists():
            return []
        return json.loads(self.manifest_path.read_text(encoding="utf-8"))["segments"]

    def _save_manifest(self) -> None:
        atomic_write(
            self.manifest_path, json.dumps({"segments": self.segments}, indent=2)
        )

    def _recover_orphans(self) -> None:
        known = {entry["name"] for entry in self.segments}
        prev = self.segments[-1]["root"] if self.segments else "GENESIS"
        for path in sorted(self.dir.glob("wal-*.jsonl*")):
            if path.name in known:
                continue
            if path.suffix == ".jsonl":
                data = path.read_bytes()
                committed = data.rfind(b"\n") + 1
                if committed != len(data):
                    with path.open("r+b") as handle:
                        handle.truncate(committed)
                        handle.flush()
                        os.fsync(handle.fileno())
            count, start = 0, prev
            for line in _read_lines(path):
                if not line.strip():
                    continue
                envelope = json.loads(line)
                expected = record_hash(prev, envelope["event"])
                if envelope["prev"] != prev or envelope["record_hash"] != expected:
                    raise ValueError(f"corrupt orphan WAL segment: {path.name}")
                prev = expected
                count += 1
            if not count:
                path.unlink()
                sync_directory(self.dir)
                continue
            with path.open("rb") as handle:
                os.fsync(handle.fileno())
            self.segments.append(
                {
                    "seq": int(path.name.split("-")[1].split(".")[0]),
                    "name": path.name,
                    "count": count,
                    "bytes": path.stat().st_size,
                    "prev_root": start,
                    "root": prev,
                }
            )
            self._save_manifest()

    def _open_segment(self) -> None:
        self._seq += 1
        self._path = self.dir / _segment_name(self._seq)
        self._fh = open(self._path, "xb")
        sync_directory(self.dir)
        self._count = 0
        self._bytes = 0
        self._opened_at = time.time()
        self._segment_prev = self._prev

    def _roll_if_needed(self) -> None:
        if self._fh is None:
            self._open_segment()
        elif (
            self._bytes >= self.max_bytes
            or (time.time() - self._opened_at) >= self.max_age_s
        ):
            self.roll()
            self._open_segment()

    def append(self, event: dict) -> dict:
        """Append one normalized event; returns its envelope."""
        if self._failed:
            raise RuntimeError("WAL writer requires recovery after a failed write")
        self._roll_if_needed()
        envelope = {
            "source_id": event["source_id"],
            "source_seq": event["source_seq"],
            "ingest_ts": event["ingest_ts"],
            "event": event,
            "prev": self._prev,
            "record_hash": record_hash(self._prev, event),
        }
        line = (
            json.dumps(
                envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
            + "\n"
        )
        data = line.encode("utf-8")
        assert self._fh is not None
        try:
            self._fh.write(data)
            self._fh.flush()
            os.fsync(self._fh.fileno())
        except BaseException:
            self._failed = True
            raise
        self._prev = envelope["record_hash"]
        self._count += 1
        self._bytes += len(data)
        return envelope

    def roll(self) -> dict | None:
        """Seal the open segment and record it in the manifest."""
        if self._fh is None:
            return None
        fh, self._fh = self._fh, None
        try:
            fh.flush()
            os.fsync(fh.fileno())
        except BaseException:
            self._failed = True
            raise
        finally:
            fh.close()
        assert self._path is not None
        entry = {
            "seq": self._seq,
            "name": self._path.name,
            "count": self._count,
            "bytes": self._path.stat().st_size,
            "prev_root": self._segment_prev,
            "root": self._prev,
        }
        self.segments.append(entry)
        self._save_manifest()
        return entry

    def close(self) -> None:
        if self._failed:
            self.abort()
            return
        if self._fh is not None:
            if self._count:
                self.roll()
            else:
                fh, self._fh = self._fh, None
                fh.close()
                assert self._path is not None
                if self._path.exists():
                    self._path.unlink()
                    sync_directory(self.dir)
                self._seq -= 1

    def abort(self) -> None:
        """Leave an unmanifested tail for verified startup recovery."""
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> "WalWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.abort() if exc and exc[0] else self.close()


class WalReader:
    """Read WAL envelopes back in segment order."""

    def __init__(self, wal_dir: str | Path) -> None:
        self.dir = Path(wal_dir)
        manifest = self.dir / MANIFEST_NAME
        self.segments: list[dict] = []
        if manifest.exists():
            self.segments = json.loads(manifest.read_text(encoding="utf-8"))["segments"]
        # Include a possibly open (unrolled) tail segment with no manifest entry.
        self._tail = sorted(self.dir.glob("wal-*.jsonl*"))

    def segment_paths(self) -> list[Path]:
        known = {s["name"] for s in self.segments}
        paths = [self.dir / s["name"] for s in self.segments]
        for path in paths:
            if not path.exists():
                raise FileNotFoundError(f"manifested WAL segment is missing: {path}")
        for path in self._tail:
            if path.name not in known:
                paths.append(path)
        return paths

    def iter_envelopes(self):
        for path in self.segment_paths():
            for lineno, line in enumerate(_read_lines(path), 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"{path}:{lineno}: invalid envelope: {exc}"
                    ) from exc

    def iter_events(self):
        for envelope in self.iter_envelopes():
            yield envelope["event"]


def verify_wal_chain(wal_dir: str | Path) -> dict:
    """Recompute every record hash and segment link. Returns a report."""
    reader = WalReader(wal_dir)
    errors: list[str] = []
    segments_checked = 0
    events = 0
    manifest = Path(wal_dir) / MANIFEST_NAME
    declared = {}
    if manifest.exists():
        for entry in json.loads(manifest.read_text(encoding="utf-8"))["segments"]:
            declared[entry["name"]] = entry
    prev_root = "GENESIS"
    for path in reader.segment_paths():
        segments_checked += 1
        prev = (
            declared.get(path.name, {}).get("prev_root", prev_root)
            if path.name in declared
            else prev_root
        )
        if path.name in declared and declared[path.name]["prev_root"] != prev_root:
            errors.append(f"{path.name}: prev_root link broken")
        count = 0
        try:
            lines = list(_read_lines(path))
        except Exception as exc:  # corrupt or truncated segment
            errors.append(f"{path.name}: unreadable: {exc}")
            continue
        for lineno, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            try:
                envelope = json.loads(line)
            except json.JSONDecodeError:
                errors.append(f"{path.name}:{lineno}: invalid JSON")
                continue
            expected = record_hash(envelope.get("prev", ""), envelope.get("event", {}))
            if envelope.get("prev") != prev:
                errors.append(f"{path.name}:{lineno}: chain link broken")
            if envelope.get("record_hash") != expected:
                errors.append(f"{path.name}:{lineno}: record hash mismatch")
            prev = envelope.get("record_hash", prev)
            count += 1
            events += 1
        if path.name in declared:
            entry = declared[path.name]
            if entry["root"] != prev:
                errors.append(f"{path.name}: segment root mismatch")
            if entry["count"] != count:
                errors.append(
                    f"{path.name}: count mismatch (manifest {entry['count']}, found {count})"
                )
        prev_root = prev
    return {
        "ok": not errors,
        "segments_checked": segments_checked,
        "events": events,
        "errors": errors,
    }
