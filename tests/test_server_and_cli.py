"""Subsystem 10: Embedded HTTP Server, OTLP Ingest, Waterfall API & Native CLI Commands."""

import gzip
import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

from snort.cli import main
from snort.server import SnortHttpHandler, SnortStoreManager


def test_server_and_cli_subsystem_endpoints_and_commands(tmp_path, capsys):
    """Verify HTTP server, /v1/traces, /v1/logs, /api/traces waterfall, /api/ai/calls, and CLI subcommands."""
    store_dir = tmp_path / "server_telemetry_store"
    store = SnortStoreManager(store_dir)

    class TestHandler(SnortHttpHandler):
        store_manager = store

    server = ThreadingHTTPServer(("127.0.0.1", 0), TestHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"

    try:
        # 1. HTML Dashboard GET / and GET /api/status
        with urllib.request.urlopen(f"{base_url}/") as resp:
            assert resp.status == 200
            html = resp.read().decode("utf-8")
            assert "snort" in html
            assert "waterfall" in html.lower()

        with urllib.request.urlopen(f"{base_url}/api/status") as resp:
            assert resp.status == 200
            status = json.loads(resp.read().decode("utf-8"))
            assert status["status"] == "online"

        # 2. Ingest OTLP Traces via POST /v1/traces
        trace_payload = {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {
                                "key": "service.name",
                                "value": {"stringValue": "payment-api"},
                            },
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
                                        {
                                            "key": "http.status_code",
                                            "value": {"intValue": 200},
                                        },
                                        {
                                            "key": "http.target",
                                            "value": {"stringValue": "/charge"},
                                        },
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
                                        {
                                            "key": "gen_ai.system",
                                            "value": {"stringValue": "openai"},
                                        },
                                        {
                                            "key": "gen_ai.request.model",
                                            "value": {"stringValue": "gpt-4o"},
                                        },
                                        {
                                            "key": "gen_ai.usage.input_tokens",
                                            "value": {"intValue": 180},
                                        },
                                        {
                                            "key": "gen_ai.usage.output_tokens",
                                            "value": {"intValue": 25},
                                        },
                                        {
                                            "key": "ai.prompt",
                                            "value": {
                                                "stringValue": "Assess transaction risk for $450"
                                            },
                                        },
                                        {
                                            "key": "ai.response",
                                            "value": {
                                                "stringValue": "Risk score: 0.02 (Low)"
                                            },
                                        },
                                    ],
                                    "status": {"code": 1},
                                },
                            ],
                        }
                    ],
                }
            ]
        }
        req_traces = urllib.request.Request(
            f"{base_url}/v1/traces",
            data=json.dumps(trace_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req_traces) as resp:
            assert resp.status == 200
            res = json.loads(resp.read().decode("utf-8"))
            assert res["ok"] is True
            assert res["insertedSpans"] == 2

        # 3. Ingest OTLP Logs via POST /v1/logs (with gzip encoding)
        log_payload = {
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [
                            {
                                "key": "service.name",
                                "value": {"stringValue": "payment-api"},
                            }
                        ]
                    },
                    "scopeLogs": [
                        {
                            "logRecords": [
                                {
                                    "timeUnixNano": "1700000000020000000",
                                    "severityText": "INFO",
                                    "body": {
                                        "stringValue": "Fraud check completed with low risk"
                                    },
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
        req_logs = urllib.request.Request(
            f"{base_url}/v1/logs",
            data=gz_data,
            headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
        )
        with urllib.request.urlopen(req_logs) as resp:
            assert resp.status == 200
            res = json.loads(resp.read().decode("utf-8"))
            assert res["ok"] is True
            assert res["insertedLogs"] == 1

        # 4. Trace Waterfall Query GET /api/traces/<trace_id>
        with urllib.request.urlopen(
            f"{base_url}/api/traces/4bf92f3577b34da6a3ce929d0e0e4736"
        ) as resp:
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

        # 5. AI Inspector Query GET /api/ai/calls
        with urllib.request.urlopen(f"{base_url}/api/ai/calls") as resp:
            assert resp.status == 200
            ai_calls = json.loads(resp.read().decode("utf-8"))
            assert len(ai_calls) == 1
            call = ai_calls[0]
            assert call["provider"] == "openai"
            assert call["model"] == "gpt-4o"
            assert call["input_tokens"] == 180
            assert call["output_tokens"] == 25
            assert call["total_tokens"] == 205
            assert "Assess transaction risk" in call["prompt"]

        # 6. Live Search on Telemetry WAL
        with urllib.request.urlopen(f"{base_url}/api/search?q=fraud") as resp:
            assert resp.status == 200
            hits = json.loads(resp.read().decode("utf-8"))
            assert len(hits) >= 1
            assert "fraud" in hits[0]["raw"].lower()

    finally:
        server.shutdown()
        server.server_close()
        store.close()

    # 7. CLI Native Commands (traces, spans, logs)
    data_dir_str = str(store_dir)

    # CLI 'snort traces'
    ret = main(["traces", "--data-dir", data_dir_str])
    assert ret == 0
    out = capsys.readouterr().out
    assert "TRACE ID" in out
    assert "4bf92f3577b34da6a3ce929d0e0e4736" in out

    # CLI 'snort spans <trace_id>'
    ret = main(
        ["spans", "4bf92f3577b34da6a3ce929d0e0e4736", "--data-dir", data_dir_str]
    )
    assert ret == 0
    out = capsys.readouterr().out
    assert "POST /charge" in out
    assert "ai.fraud_check" in out

    # CLI 'snort logs --trace-id <trace_id>'
    ret = main(
        [
            "logs",
            "--trace-id",
            "4bf92f3577b34da6a3ce929d0e0e4736",
            "--data-dir",
            data_dir_str,
        ]
    )
    assert ret == 0
    out = capsys.readouterr().out
    assert "Fraud check completed" in out
