"""OTLP HTTP traces and logs adapter for snort subsystems."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
from typing import Any, Mapping


SPAN_KIND_LABELS = {
    1: "internal",
    2: "server",
    3: "client",
    4: "producer",
    5: "consumer",
}


def normalize_otlp_id(val: Any, expected_bytes: int) -> str:
    """Normalize hex or base64 binary IDs into a lowercase hex string."""
    if val is None:
        return ""
    text = str(val).strip()
    if not text:
        return ""
    expected_hex = expected_bytes * 2
    # If already expected hex
    if len(text) == expected_hex and all(c in "0123456789abcdefABCDEF" for c in text):
        return text.lower()
    # Try decoding base64 binary representation
    try:
        raw = base64.b64decode(text)
        if len(raw) == expected_bytes:
            return raw.hex()
    except Exception:
        pass
    return text.lower()


def parse_any_value(val: Any) -> Any:
    """Unnest OTLP AnyValue schema into Python native types."""
    if val is None:
        return None
    if not isinstance(val, dict):
        return val

    if "stringValue" in val:
        return val["stringValue"]
    if "boolValue" in val:
        return bool(val["boolValue"])
    if "intValue" in val:
        try:
            return int(val["intValue"])
        except (ValueError, TypeError):
            return val["intValue"]
    if "doubleValue" in val:
        try:
            return float(val["doubleValue"])
        except (ValueError, TypeError):
            return val["doubleValue"]
    if "bytesValue" in val:
        return val["bytesValue"]
    if "arrayValue" in val:
        values = val["arrayValue"].get("values", [])
        return [parse_any_value(item) for item in values]
    if "kvlistValue" in val:
        values = val["kvlistValue"].get("values", [])
        return {
            item.get("key", ""): parse_any_value(item.get("value"))
            for item in values
            if "key" in item
        }
    return val


def parse_otlp_attributes(kvs: Any) -> dict[str, Any]:
    """Parse list of KeyValue objects or dict of attributes."""
    attrs: dict[str, Any] = {}
    if not kvs:
        return attrs
    if isinstance(kvs, dict):
        for k, v in kvs.items():
            attrs[str(k)] = parse_any_value(v)
        return attrs
    if isinstance(kvs, list):
        for entry in kvs:
            if isinstance(entry, dict) and "key" in entry:
                key = str(entry["key"])
                attrs[key] = parse_any_value(entry.get("value"))
    return attrs


def nanos_to_iso(nanos_val: Any) -> str:
    """Convert nanoseconds timestamp to ISO-8601 UTC string."""
    if nanos_val is None:
        return datetime.now(timezone.utc).isoformat()
    try:
        nanos = int(nanos_val)
        seconds = nanos / 1_000_000_000.0
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    except Exception:
        if isinstance(nanos_val, str) and ("T" in nanos_val or "-" in nanos_val):
            return nanos_val
        return datetime.now(timezone.utc).isoformat()


def detect_ai_metadata(attrs: dict[str, Any]) -> dict[str, Any] | None:
    """Extract AI / LLM call metrics if present in span attributes."""
    provider = (
        attrs.get("gen_ai.system")
        or attrs.get("ai.provider")
        or attrs.get("llm.provider")
        or attrs.get("ai.model.provider")
    )
    model = (
        attrs.get("gen_ai.request.model")
        or attrs.get("gen_ai.response.model")
        or attrs.get("ai.model.id")
        or attrs.get("llm.model")
        or attrs.get("model")
    )
    prompt = (
        attrs.get("gen_ai.prompt")
        or attrs.get("ai.prompt")
        or attrs.get("prompt")
        or attrs.get("gen_ai.request.prompt")
    )
    completion = (
        attrs.get("gen_ai.completion")
        or attrs.get("ai.response")
        or attrs.get("response")
        or attrs.get("gen_ai.response.completion")
    )

    in_tokens = (
        attrs.get("gen_ai.usage.input_tokens")
        or attrs.get("gen_ai.usage.prompt_tokens")
        or attrs.get("ai.usage.promptTokens")
        or attrs.get("llm.token_count.prompt")
    )
    out_tokens = (
        attrs.get("gen_ai.usage.output_tokens")
        or attrs.get("gen_ai.usage.completion_tokens")
        or attrs.get("ai.usage.completionTokens")
        or attrs.get("llm.token_count.completion")
    )

    if not any((provider, model, prompt, completion, in_tokens, out_tokens)):
        return None

    def _to_int(v: Any) -> int:
        try:
            return int(v) if v is not None else 0
        except (ValueError, TypeError):
            return 0

    in_cnt = _to_int(in_tokens)
    out_cnt = _to_int(out_tokens)
    total_cnt = _to_int(
        attrs.get("gen_ai.usage.total_tokens")
        or attrs.get("ai.usage.totalTokens")
        or attrs.get("llm.token_count.total")
        or (in_cnt + out_cnt)
    )

    prompt_str = str(prompt) if prompt is not None else ""
    comp_str = str(completion) if completion is not None else ""

    return {
        "is_ai_call": True,
        "ai_provider": str(provider or "unknown"),
        "ai_model": str(model or "unknown"),
        "ai_input_tokens": in_cnt,
        "ai_output_tokens": out_cnt,
        "ai_total_tokens": total_cnt,
        "ai_prompt": prompt_str,
        "ai_completion": comp_str,
        "ai_prompt_preview": (prompt_str[:120] + "...") if len(prompt_str) > 120 else prompt_str,
        "ai_completion_preview": (comp_str[:120] + "...") if len(comp_str) > 120 else comp_str,
    }


def parse_otlp_traces(payload: Any) -> list[dict[str, Any]]:
    """Parse standard OTLP ExportTraceServiceRequest JSON into snort events.

    Maps `session_id = trace_id` and `session_root = parent_span_id or span_id`
    so Snort's trace assembler, Lance columnar storage, and DuckDB unified
    search automatically assemble and query the distributed traces.
    """
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        items = [payload]
    else:
        return []

    events: list[dict[str, Any]] = []

    for item in items:
        resource_spans = item.get("resourceSpans", [])
        if not isinstance(resource_spans, list):
            continue

        for res_span in resource_spans:
            if not isinstance(res_span, dict):
                continue
            resource = res_span.get("resource", {})
            res_attrs = parse_otlp_attributes(resource.get("attributes"))
            service_name = str(res_attrs.get("service.name") or "unknown_service")
            host_name = str(
                res_attrs.get("host.name")
                or res_attrs.get("host.id")
                or res_attrs.get("service.instance.id")
                or "localhost"
            )

            scope_spans = res_span.get("scopeSpans", [])
            if not isinstance(scope_spans, list):
                continue

            for scope_span in scope_spans:
                if not isinstance(scope_span, dict):
                    continue
                scope = scope_span.get("scope", {})
                scope_name = str(scope.get("name") or "")
                spans = scope_span.get("spans", [])
                if not isinstance(spans, list):
                    continue

                for span in spans:
                    if not isinstance(span, dict):
                        continue
                    trace_id = normalize_otlp_id(span.get("traceId"), 16)
                    span_id = normalize_otlp_id(span.get("spanId"), 8)
                    parent_id = normalize_otlp_id(span.get("parentSpanId"), 8)
                    span_name = str(span.get("name") or "span")

                    start_nano = span.get("startTimeUnixNano", 0)
                    end_nano = span.get("endTimeUnixNano", start_nano)
                    try:
                        s_int = int(start_nano)
                        e_int = int(end_nano)
                        duration_ms = max(0.0, (e_int - s_int) / 1_000_000.0)
                    except (ValueError, TypeError):
                        duration_ms = 0.0

                    kind_int = span.get("kind", 1)
                    kind_label = SPAN_KIND_LABELS.get(kind_int, "internal")

                    status_obj = span.get("status", {})
                    status_code = status_obj.get("code", 0) if isinstance(status_obj, dict) else 0
                    status_msg = str(status_obj.get("message") or "") if isinstance(status_obj, dict) else ""
                    # OTLP status: 0=UNSET, 1=OK, 2=ERROR
                    status_label = "error" if status_code == 2 else "ok"

                    span_attrs = parse_otlp_attributes(span.get("attributes"))

                    # Combine all attributes
                    combined_attrs: dict[str, Any] = {}
                    combined_attrs.update(res_attrs)
                    combined_attrs.update(span_attrs)
                    combined_attrs.update({
                        "trace_id": trace_id,
                        "span_id": span_id,
                        "parent_span_id": parent_id,
                        "span_kind": kind_label,
                        "duration_ms": round(duration_ms, 3),
                        "status": status_label,
                        "status_code": status_code,
                        "status_message": status_msg,
                        "scope_name": scope_name,
                        "service_name": service_name,
                        # Crucial bridging for Snort's Trace Assembler
                        "session_id": trace_id,
                        "session_root": parent_id or span_id,
                    })

                    # Detect and merge AI metadata if present
                    ai_meta = detect_ai_metadata(combined_attrs)
                    if ai_meta:
                        combined_attrs.update(ai_meta)

                    # Extract events (e.g. exception events)
                    raw_events = span.get("events")
                    if isinstance(raw_events, list) and raw_events:
                        parsed_events = []
                        for ev in raw_events:
                            if isinstance(ev, dict):
                                parsed_events.append({
                                    "name": str(ev.get("name") or ""),
                                    "time_iso": nanos_to_iso(ev.get("timeUnixNano")),
                                    "attributes": parse_otlp_attributes(ev.get("attributes")),
                                })
                        combined_attrs["events"] = parsed_events

                    # Target object (URL, query, table, or operation)
                    obj_target = (
                        span_attrs.get("http.target")
                        or span_attrs.get("http.route")
                        or span_attrs.get("db.system")
                        or span_attrs.get("rpc.method")
                        or span_name
                    )

                    raw_desc = (
                        f"[{status_label.upper()}] {service_name}:{span_name} "
                        f"({duration_ms:.2f}ms)"
                    )
                    if ai_meta:
                        raw_desc += f" [ai:{ai_meta['ai_model']} tokens:{ai_meta['ai_total_tokens']}]"

                    events.append({
                        "ts": nanos_to_iso(start_nano),
                        "host": host_name,
                        "source_id": service_name,
                        "action": span_name,
                        "subject": service_name,
                        "object": str(obj_target),
                        "session_id": trace_id,
                        "session_root": parent_id or span_id,
                        "attributes": combined_attrs,
                        "raw": raw_desc,
                    })

    return events


def parse_otlp_logs(payload: Any) -> list[dict[str, Any]]:
    """Parse standard OTLP ExportLogsServiceRequest JSON into snort events."""
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        items = [payload]
    else:
        return []

    events: list[dict[str, Any]] = []

    for item in items:
        resource_logs = item.get("resourceLogs", [])
        if not isinstance(resource_logs, list):
            continue

        for res_log in resource_logs:
            if not isinstance(res_log, dict):
                continue
            resource = res_log.get("resource", {})
            res_attrs = parse_otlp_attributes(resource.get("attributes"))
            service_name = str(res_attrs.get("service.name") or "unknown_service")
            host_name = str(
                res_attrs.get("host.name")
                or res_attrs.get("host.id")
                or "localhost"
            )

            scope_logs = res_log.get("scopeLogs", [])
            if not isinstance(scope_logs, list):
                continue

            for scope_log in scope_logs:
                if not isinstance(scope_log, dict):
                    continue
                scope = scope_log.get("scope", {})
                scope_name = str(scope.get("name") or "")
                log_records = scope_log.get("logRecords", [])
                if not isinstance(log_records, list):
                    continue

                for log_record in log_records:
                    if not isinstance(log_record, dict):
                        continue
                    trace_id = normalize_otlp_id(log_record.get("traceId"), 16)
                    span_id = normalize_otlp_id(log_record.get("spanId"), 8)
                    time_nano = log_record.get("timeUnixNano") or log_record.get("observedTimeUnixNano")

                    severity = str(log_record.get("severityText") or "INFO").upper()
                    body_val = parse_any_value(log_record.get("body"))
                    log_attrs = parse_otlp_attributes(log_record.get("attributes"))

                    combined_attrs: dict[str, Any] = {}
                    combined_attrs.update(res_attrs)
                    combined_attrs.update(log_attrs)
                    combined_attrs.update({
                        "scope_name": scope_name,
                        "service_name": service_name,
                        "severity": severity,
                    })
                    if trace_id:
                        combined_attrs["trace_id"] = trace_id
                        combined_attrs["session_id"] = trace_id
                    if span_id:
                        combined_attrs["span_id"] = span_id
                        combined_attrs["session_root"] = span_id

                    body_str = (
                        json.dumps(body_val)
                        if isinstance(body_val, (dict, list))
                        else str(body_val or "")
                    )

                    event: dict[str, Any] = {
                        "ts": nanos_to_iso(time_nano),
                        "host": host_name,
                        "source_id": service_name,
                        "action": f"log.{severity.lower()}",
                        "subject": service_name,
                        "object": scope_name or "stdout",
                        "attributes": combined_attrs,
                        "raw": f"[{severity}] {body_str}" if body_str else f"[{severity}]",
                    }
                    if trace_id:
                        event["session_id"] = trace_id
                    if span_id:
                        event["session_root"] = span_id

                    events.append(event)

    return events
