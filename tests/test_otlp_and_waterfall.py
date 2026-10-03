"""End-to-end tests for OTLP ingest, Trace Waterfall, AI call inspection, and CLI commands."""

import gzip
import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from snort.cli import main
from snort.ingest.otlp import (
    detect_ai_metadata,
    normalize_otlp_id,
    parse_any_value,
    parse_otlp_attributes,
    parse_otlp_logs,
    parse_otlp_traces,
)
from snort.server import SnortHttpHandler, SnortStoreManager


def test_otlp_id_normalization():
    # 16 bytes = 32 hex chars
    hex_trace = "4bf92f3577b34da6a3ce929d0e0e4736"
    assert normalize_otlp_id(hex_trace, 16) == hex_trace
    assert normalize_otlp_id(hex_trace.upper(), 16) == hex_trace

    # Base64 encoded binary 16 bytes
    b64_trace = "S/kvNXezTaajzpKdDg5HNg=="
    assert normalize_otlp_id(b64_trace, 16) == hex_trace

    # 8 bytes = 16 hex chars
    hex_span = "00f067aa0ba902b7"
    assert normalize_otlp_id(hex_span, 8) == hex_span

    # Empty
    assert normalize_otlp_id("", 16) == ""
    assert normalize_otlp_id(None, 16) == ""


def test_otlp_any_value_and_attributes():
    raw_kvs = [
        {"key": "str_key", "value": {"stringValue": "hello"}},
        {"key": "int_key", "value": {"intValue": "42"}},
        {"key": "bool_key", "value": {"boolValue": True}},
        {"key": "float_key", "value": {"doubleValue": 3.14}},
        {"key": "arr_key", "value": {"arrayValue": {"values": [{"stringValue": "a"}, {"stringValue": "b"}]}}},
        {"key": "kv_key", "value": {"kvlistValue": {"values": [{"key": "inner", "value": {"stringValue": "val"}}]}}},
    ]
    parsed = parse_otlp_attributes(raw_kvs)
    assert parsed["str_key"] == "hello"
    assert parsed["int_key"] == 42
    assert parsed["bool_key"] is True
    assert abs(parsed["float_key"] - 3.14) < 1e-4
    assert parsed["arr_key"] == ["a", "b"]
    assert parsed["kv_key"] == {"inner": "val"}


def test_ai_metadata_detection():
    attrs = {
        "gen_ai.system": "anthropic",
        "gen_ai.request.model": "claude-3-7-sonnet",
        "gen_ai.usage.input_tokens": 120,
        "gen_ai.usage.output_tokens": 45,
        "ai.prompt": "Summarize logs",
        "ai.response": "All systems operational.",
    }
    ai_meta = detect_ai_metadata(attrs)
    assert ai_meta is not None
    assert ai_meta["is_ai_call"] is True
    assert ai_meta["ai_provider"] == "anthropic"
    assert ai_meta["ai_model"] == "claude-3-7-sonnet"
    assert ai_meta["ai_input_tokens"] == 120
    assert ai_meta["ai_output_tokens"] == 45
    assert ai_meta["ai_total_tokens"] == 165
    assert "Summarize" in ai_meta["ai_prompt"]


def test_otlp_server_endpoints(tmp_path):
    store = SnortStoreManager(tmp_path / "telemetry_store")

    class TestHandler(SnortHttpHandler):
        store_manager = store

    server = ThreadingHTTPServer(("127.0.0.1", 0), TestHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"

    try:
        # 1. Ingest OTLP Traces via POST /v1/traces
        trace_payload = {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "payment-api"}},
                            {"key": "host.name", "value": {"stringValue": "node-01"}},
                        ]
                    },
                    "scopeSpans": [
                        {
                            "scope": {"name": "express"},
                            "spans": [
                                {
                                    "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
                                    "spanId": "00f067aa0ba902b7",
                                    "name": "POST /charge",
                                    "kind": 2,
                                    "startTimeUnixNano": "1700000000000000000",
                                    "endTimeUnixNano": "1700000000060000000",
                                    "attributes": [
                                        {"key": "http.status_code", "value": {"intValue": 200}},
                                        {"key": "http.target", "value": {"stringValue": "/charge"}},
                                    ],
                                    "status": {"code": 1},
                                },
                                {
                                    "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
                                    "spanId": "5fb397be34d23b0f",
                                    "parentSpanId": "00f067aa0ba902b7",
                                    "name": "ai.fraud_check",
                                    "kind": 3,
                                    "startTimeUnixNano": "1700000000010000000",
                                    "endTimeUnixNano": "1700000000045000000",
                                    "attributes": [
                                        {"key": "gen_ai.system", "value": {"stringValue": "openai"}},
                                        {"key": "gen_ai.request.model", "value": {"stringValue": "gpt-4o"}},
                                        {"key": "gen_ai.usage.input_tokens", "value": {"intValue": 180}},
                                        {"key": "gen_ai.usage.output_tokens", "value": {"intValue": 25}},
                                        {"key": "ai.prompt", "value": {"stringValue": "Assess transaction risk for $450"}},
                                        {"key": "ai.response", "value": {"stringValue": "Risk score: 0.02 (Low)"}},
                                    ],
                                    "status": {"code": 1},
                                },
                            ],
                        }
                    ],
                }
            ]
        }
        data = json.dumps(trace_payload).encode("utf-8")
        req = urllib.request.Request(
            f"{base_url}/v1/traces",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            res = json.loads(resp.read().decode("utf-8"))
            assert res["ok"] is True
            assert res["insertedSpans"] == 2

        # 2. Ingest OTLP Logs via POST /v1/logs (with gzip encoding)
        log_payload = {
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [{"key": "service.name", "value": {"stringValue": "payment-api"}}]
                    },
                    "scopeLogs": [
                        {
                            "logRecords": [
                                {
                                    "timeUnixNano": "1700000000020000000",
                                    "severityText": "INFO",
                                    "body": {"stringValue": "Fraud check completed with low risk"},
                                    "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
                                    "spanId": "5fb397be34d23b0f",
                                }
                            ]
                        }
                    ],
                }
            ]
        }
        gz_data = gzip.compress(json.dumps(log_payload).encode("utf-8"))
        req = urllib.request.Request(
            f"{base_url}/v1/logs",
            data=gz_data,
            headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
        )
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            res = json.loads(resp.read().decode("utf-8"))
            assert res["ok"] is True
            assert res["insertedLogs"] == 1

        # 3. Query GET /api/services
        with urllib.request.urlopen(f"{base_url}/api/services") as resp:
            assert resp.status == 200
            services = json.loads(resp.read().decode("utf-8"))
            assert any(s["name"] == "payment-api" for s in services)

        # 4. Query GET /api/traces
        with urllib.request.urlopen(f"{base_url}/api/traces") as resp:
            assert resp.status == 200
            traces = json.loads(resp.read().decode("utf-8"))
            assert len(traces) >= 1
            t = next(x for x in traces if x["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736")
            assert t["service"] == "payment-api"
            assert t["span_count"] == 2
            assert t["status"] == "ok"
            assert t["ai_call_count"] == 1

        # 5. Query GET /api/traces/<trace_id> (full tree waterfall)
        with urllib.request.urlopen(f"{base_url}/api/traces/4bf92f3577b34da6a3ce929d0e0e4736") as resp:
            assert resp.status == 200
            tree = json.loads(resp.read().decode("utf-8"))
            assert tree["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"
            assert len(tree["spans"]) == 2
            root = tree["spans"][0]
            child = tree["spans"][1]
            assert root["depth"] == 0
            assert root["name"] == "POST /charge"
            assert child["depth"] == 1
            assert child["name"] == "ai.fraud_check"
            assert child["is_ai_call"] is True
            assert len(child["logs"]) == 1
            assert "Fraud check completed" in child["logs"][0]["raw"]

        # 6. Query GET /api/spans/<span_id>
        with urllib.request.urlopen(f"{base_url}/api/spans/5fb397be34d23b0f") as resp:
            assert resp.status == 200
            span = json.loads(resp.read().decode("utf-8"))
            assert span["action"] == "ai.fraud_check"
            assert span["attributes"]["span_id"] == "5fb397be34d23b0f"
            assert len(span["correlated_logs"]) == 1

        # 7. Query GET /api/ai/calls
        with urllib.request.urlopen(f"{base_url}/api/ai/calls") as resp:
            assert resp.status == 200
            ai_calls = json.loads(resp.read().decode("utf-8"))
            assert len(ai_calls) == 1
            ai_call = ai_calls[0]
            assert ai_call["model"] == "gpt-4o"
            assert ai_call["provider"] == "openai"
            assert ai_call["input_tokens"] == 180
            assert ai_call["output_tokens"] == 25
            assert ai_call["total_tokens"] == 205
            assert "Assess transaction risk" in ai_call["prompt"]

        # 8. Query GET /api/logs
        with urllib.request.urlopen(f"{base_url}/api/logs") as resp:
            assert resp.status == 200
            logs = json.loads(resp.read().decode("utf-8"))
            assert len(logs) == 1
            assert logs[0]["service"] == "payment-api"
            assert logs[0]["severity"] == "INFO"

        # 9. Verify unified search finds the span & log content
        with urllib.request.urlopen(f"{base_url}/api/search?q=fraud") as resp:
            assert resp.status == 200
            hits = json.loads(resp.read().decode("utf-8"))
            assert len(hits) >= 1
            assert "fraud" in hits[0]["raw"].lower()

    finally:
        server.shutdown()
        server.server_close()
        store.close()


def test_cli_subcommands(tmp_path, capsys):
    data_dir = str(tmp_path / "cli_store")
    with SnortStoreManager(data_dir) as store:
        # Load demo OTLP traces and logs
        res = store.demo_otlp()
        assert res["traces_loaded"] >= 1

    # Test 'snort traces'
    ret = main(["traces", "--data-dir", data_dir])
    assert ret == 0
    out = capsys.readouterr().out
    assert "TRACE ID" in out
    assert "checkout-api" in out

    # Test 'snort traces --json'
    ret = main(["traces", "--data-dir", data_dir, "--json"])
    assert ret == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert len(data) >= 1

    # Test 'snort spans --trace-id <id>' (ASCII Waterfall tree)
    ret = main(["spans", "--trace-id", "4bf92f3577b34da6a3ce929d0e0e4736", "--data-dir", data_dir])
    assert ret == 0
    out = capsys.readouterr().out
    assert "TRACE: 4bf92f3577b34da6a3ce929d0e0e4736" in out
    assert "POST /api/v1/checkout" in out
    assert "ai.suggest_bundles" in out
    assert "claude-3-7-sonnet" in out

    # Test 'snort spans <span_id>'
    ret = main(["spans", "7c8b21ef45a30129", "--data-dir", data_dir])
    assert ret == 0
    out = capsys.readouterr().out
    assert "SPAN: 7c8b21ef45a30129" in out
    assert "ai.suggest_bundles" in out

    # Test 'snort logs'
    ret = main(["logs", "--data-dir", data_dir])
    assert ret == 0
    out = capsys.readouterr().out
    assert "ERROR" in out
    assert "ldap" in out.lower()

    # Test 'snort services'
    ret = main(["services", "--data-dir", data_dir])
    assert ret == 0
    out = capsys.readouterr().out
    assert "checkout-api" in out
    assert "auth-service" in out

    # Test 'snort ai'
    ret = main(["ai", "--data-dir", data_dir])
    assert ret == 0
    out = capsys.readouterr().out
    assert "claude-3-7-sonnet" in out
    assert "anthropic" in out
