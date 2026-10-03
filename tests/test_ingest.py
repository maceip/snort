"""Subsystem Test: Ingest (Canonical Normalization, SCLC, FluxSieve, CLAD, WAL, OTLP)."""

from pathlib import Path

from snort.ingest.events import (
    EVENT_COLUMNS,
    FLUX_TAG_AI,
    FLUX_TAG_ATTACK,
    FLUX_TAG_ERROR,
    FLUX_TAG_NETWORK,
    compute_compression_deviation,
    normalize_event,
    normalize_sclc,
)
from snort.ingest.otlp import (
    detect_ai_metadata,
    parse_otlp_traces,
)
from snort.ingest.wal import WalReader, WalWriter, verify_wal_chain


def test_ingest_subsystem(tmp_path: Path):
    """Real end-to-end test of the entire ingest subsystem."""
    # 1. SCLC command normalization (Unveiling-CTAs)
    raw_cmd = "powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\admin\\AppData\\Local\\Temp\\setup.ps1 -Connect 192.168.1.100:4444"
    normalized_cmd = normalize_sclc(raw_cmd)
    assert "<FILE_PATH>" in normalized_cmd
    assert "<IP>" in normalized_cmd
    assert "192.168.1.100" not in normalized_cmd

    # 2. CLAD zero-decompression byte entropy and compression check
    repetitive_bytes = b"INFO benign standard system logging timestamp event ok " * 20
    ent_low, ratio_low, anom_low = compute_compression_deviation(repetitive_bytes)
    assert not anom_low
    assert ent_low < 5.0
    assert ratio_low < 0.5  # Compresses well

    # Equal-frequency bytes give deterministic high entropy without random flakes.
    high_entropy_bytes = bytes(range(256))
    ent_high, ratio_high, anom_high = compute_compression_deviation(high_entropy_bytes)
    assert ent_high > 7.0
    assert ratio_high > 0.9
    assert anom_high

    # 3. Canonical normalization and FluxSieve 32-bit bitmask tags
    sample_raw = {
        "ts": "2026-10-03T12:00:00Z",
        "host": "prod-app-01",
        "action": "powershell_exec",
        "subject": "user:svc_web",
        "object": "socket:10.0.0.5:8080",
        "raw": "powershell.exe whoami /priv error connecting to 10.0.0.5:8080",
        "attributes": {
            "session_id": "session-123",
            "technique_ids": ["T1059.001"],
            "remote_ip": "10.0.0.5",
            "gen_ai.model": "gpt-4o",
            "gen_ai.prompt_tokens": 150,
        },
    }
    event = normalize_event(sample_raw)
    assert set(event.keys()) == set(EVENT_COLUMNS)
    assert event["event_hash"]
    assert event["template_hash"]

    # Verify FluxSieve tags were bitwise combined
    tags = event["flux_tags"]
    assert tags & FLUX_TAG_ERROR  # "error" in text
    assert tags & FLUX_TAG_ATTACK  # "powershell", "whoami", T1059.001
    assert tags & FLUX_TAG_NETWORK  # remote_ip
    assert tags & FLUX_TAG_AI  # gen_ai.*

    # 4. Durable WAL append-only writer, reader, and tamper detection
    wal_dir = tmp_path / "wal"
    writer = WalWriter(wal_dir, max_bytes=50_000)
    for i in range(10):
        ev = dict(event, source_seq=i)
        writer.append(ev)
    writer.close()

    reader = WalReader(wal_dir)
    read_events = list(reader.iter_events())
    assert len(read_events) == 10
    assert verify_wal_chain(wal_dir)["ok"]

    # Tamper detection
    seg_file = list(wal_dir.glob("wal-*.jsonl"))[0]
    data = bytearray(seg_file.read_bytes())
    data[-1] ^= 0xFF
    seg_file.write_bytes(bytes(data))
    assert not verify_wal_chain(wal_dir)["ok"]

    # 5. OTLP trace & log ingestion
    otlp_trace_payload = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {
                            "key": "service.name",
                            "value": {"stringValue": "checkout-svc"},
                        }
                    ]
                },
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
                                "spanId": "00f067aa0ba902b7",
                                "name": "process_payment",
                                "startTimeUnixNano": "1727956800000000000",
                                "endTimeUnixNano": "1727956801500000000",
                                "attributes": [
                                    {
                                        "key": "gen_ai.system",
                                        "value": {"stringValue": "openai"},
                                    },
                                    {
                                        "key": "gen_ai.request.model",
                                        "value": {"stringValue": "gpt-4o"},
                                    },
                                    {
                                        "key": "gen_ai.usage.prompt_tokens",
                                        "value": {"intValue": 210},
                                    },
                                    {
                                        "key": "gen_ai.usage.completion_tokens",
                                        "value": {"intValue": 45},
                                    },
                                ],
                            }
                        ]
                    }
                ],
            }
        ]
    }
    parsed_spans = parse_otlp_traces(otlp_trace_payload)
    assert len(parsed_spans) == 1
    span = parsed_spans[0]
    assert span["action"] == "process_payment"
    assert (
        span["session_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"
    )  # trace_id mapped to session_id
    assert span["attributes"]["gen_ai.usage.prompt_tokens"] == 210
    ai_meta = detect_ai_metadata(span["attributes"])
    assert ai_meta is not None
    assert ai_meta["is_ai_call"] is True
    assert ai_meta["ai_input_tokens"] == 210
    assert ai_meta["ai_output_tokens"] == 45
