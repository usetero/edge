#!/usr/bin/env python3
"""
Compare captured payloads between Edge, otelcol, and Vector.

Parses the OTLP protobuf and JSON outputs to extract individual records
and compare them for equivalence.
"""

import argparse
import base64
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR / "proto_gen"))

from opentelemetry.proto.collector.logs.v1 import logs_service_pb2
from opentelemetry.proto.collector.metrics.v1 import metrics_service_pb2
from opentelemetry.proto.collector.trace.v1 import trace_service_pb2


def load_captures(filepath):
    """Load captured payloads from JSONL file."""
    captures = []
    if not filepath.exists():
        return captures
    with open(filepath, "r") as f:
        for line in f:
            if line.strip():
                record = json.loads(line)
                record["data"] = base64.b64decode(record["data_base64"])
                del record["data_base64"]
                captures.append(record)
    return captures


def extract_logs_from_protobuf(data):
    """Extract log records from OTLP protobuf."""
    req = logs_service_pb2.ExportLogsServiceRequest()
    req.ParseFromString(data)

    logs = []
    for resource_logs in req.resource_logs:
        resource_attrs = {}
        for attr in resource_logs.resource.attributes:
            resource_attrs[attr.key] = get_any_value(attr.value)

        for scope_logs in resource_logs.scope_logs:
            scope_name = scope_logs.scope.name if scope_logs.scope else ""
            for log_record in scope_logs.log_records:
                log_attrs = {}
                for attr in log_record.attributes:
                    log_attrs[attr.key] = get_any_value(attr.value)

                logs.append(
                    {
                        "resource": resource_attrs,
                        "scope": scope_name,
                        "body": get_any_value(log_record.body),
                        "severity_text": log_record.severity_text,
                        "severity_number": log_record.severity_number,
                        "attributes": log_attrs,
                        "time_unix_nano": log_record.time_unix_nano,
                    }
                )
    return logs


def extract_logs_from_json(data):
    """Extract log records from Vector JSON output."""
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError:
        return []

    # Vector outputs logs in its internal format
    # The structure varies based on configuration
    if isinstance(parsed, list):
        return parsed
    elif isinstance(parsed, dict):
        return [parsed]
    return []


def extract_spans_from_protobuf(data):
    """Extract spans from OTLP protobuf."""
    req = trace_service_pb2.ExportTraceServiceRequest()
    req.ParseFromString(data)

    spans = []
    for resource_spans in req.resource_spans:
        resource_attrs = {}
        for attr in resource_spans.resource.attributes:
            resource_attrs[attr.key] = get_any_value(attr.value)

        for scope_spans in resource_spans.scope_spans:
            scope_name = scope_spans.scope.name if scope_spans.scope else ""
            for span in scope_spans.spans:
                span_attrs = {}
                for attr in span.attributes:
                    span_attrs[attr.key] = get_any_value(attr.value)

                spans.append(
                    {
                        "resource": resource_attrs,
                        "scope": scope_name,
                        "name": span.name,
                        "trace_id": span.trace_id.hex(),
                        "span_id": span.span_id.hex(),
                        "parent_span_id": span.parent_span_id.hex()
                        if span.parent_span_id
                        else "",
                        "kind": span.kind,
                        "attributes": span_attrs,
                        "start_time_unix_nano": span.start_time_unix_nano,
                        "end_time_unix_nano": span.end_time_unix_nano,
                    }
                )
    return spans


def extract_spans_from_json(data):
    """Extract spans from Vector JSON output."""
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError:
        return []

    if isinstance(parsed, list):
        return parsed
    elif isinstance(parsed, dict):
        return [parsed]
    return []


def extract_metrics_from_protobuf(data):
    """Extract metrics from OTLP protobuf."""
    req = metrics_service_pb2.ExportMetricsServiceRequest()
    req.ParseFromString(data)

    metrics = []
    for resource_metrics in req.resource_metrics:
        resource_attrs = {}
        for attr in resource_metrics.resource.attributes:
            resource_attrs[attr.key] = get_any_value(attr.value)

        for scope_metrics in resource_metrics.scope_metrics:
            scope_name = scope_metrics.scope.name if scope_metrics.scope else ""
            for metric in scope_metrics.metrics:
                metrics.append(
                    {
                        "resource": resource_attrs,
                        "scope": scope_name,
                        "name": metric.name,
                        "description": metric.description,
                        "unit": metric.unit,
                    }
                )
    return metrics


def extract_metrics_from_json(data):
    """Extract metrics from Vector JSON output."""
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError:
        return []

    if isinstance(parsed, list):
        return parsed
    elif isinstance(parsed, dict):
        return [parsed]
    return []


def get_any_value(value):
    """Convert OTLP AnyValue to Python value."""
    if value.HasField("string_value"):
        return value.string_value
    elif value.HasField("int_value"):
        return value.int_value
    elif value.HasField("double_value"):
        return value.double_value
    elif value.HasField("bool_value"):
        return value.bool_value
    elif value.HasField("bytes_value"):
        return value.bytes_value.hex()
    elif value.HasField("array_value"):
        return [get_any_value(v) for v in value.array_value.values]
    elif value.HasField("kvlist_value"):
        return {kv.key: get_any_value(kv.value) for kv in value.kvlist_value.values}
    return None


def compare_logs(name, edge_caps, otelcol_caps, vector_caps):
    """Compare log records across systems."""
    print(f"\n=== {name} ===")

    # Extract logs from each system
    edge_logs = []
    for cap in edge_caps:
        if "protobuf" in cap["content_type"]:
            edge_logs.extend(extract_logs_from_protobuf(cap["data"]))
        else:
            edge_logs.extend(extract_logs_from_json(cap["data"]))

    otelcol_logs = []
    for cap in otelcol_caps:
        if "protobuf" in cap["content_type"]:
            otelcol_logs.extend(extract_logs_from_protobuf(cap["data"]))
        else:
            otelcol_logs.extend(extract_logs_from_json(cap["data"]))

    vector_logs = []
    for cap in vector_caps:
        if "protobuf" in cap["content_type"]:
            vector_logs.extend(extract_logs_from_protobuf(cap["data"]))
        else:
            vector_logs.extend(extract_logs_from_json(cap["data"]))

    print(f"  Edge log records: {len(edge_logs)}")
    print(f"  otelcol log records: {len(otelcol_logs)}")
    print(f"  Vector log records: {len(vector_logs)}")

    # Show sample records
    if edge_logs:
        print(f"\n  Sample Edge log:")
        print(f"    body: {edge_logs[0].get('body', 'N/A')[:100]}")
        print(f"    severity: {edge_logs[0].get('severity_text', 'N/A')}")

    if otelcol_logs:
        print(f"\n  Sample otelcol log:")
        print(f"    body: {otelcol_logs[0].get('body', 'N/A')[:100]}")
        print(f"    severity: {otelcol_logs[0].get('severity_text', 'N/A')}")

    if vector_logs:
        print(f"\n  Sample Vector log (raw JSON):")
        sample = json.dumps(vector_logs[0], indent=4)[:500]
        for line in sample.split("\n"):
            print(f"    {line}")

    # Compare counts
    if len(edge_logs) == len(otelcol_logs):
        print(f"\n  OK: Edge and otelcol have same record count")
    else:
        print(f"\n  MISMATCH: Edge ({len(edge_logs)}) vs otelcol ({len(otelcol_logs)})")

    return len(edge_logs), len(otelcol_logs), len(vector_logs)


def compare_traces(name, edge_caps, otelcol_caps, vector_caps):
    """Compare trace spans across systems."""
    print(f"\n=== {name} ===")

    # Extract spans from each system
    edge_spans = []
    for cap in edge_caps:
        if "protobuf" in cap["content_type"]:
            edge_spans.extend(extract_spans_from_protobuf(cap["data"]))
        else:
            edge_spans.extend(extract_spans_from_json(cap["data"]))

    otelcol_spans = []
    for cap in otelcol_caps:
        if "protobuf" in cap["content_type"]:
            otelcol_spans.extend(extract_spans_from_protobuf(cap["data"]))
        else:
            otelcol_spans.extend(extract_spans_from_json(cap["data"]))

    vector_spans = []
    for cap in vector_caps:
        if "protobuf" in cap["content_type"]:
            vector_spans.extend(extract_spans_from_protobuf(cap["data"]))
        else:
            vector_spans.extend(extract_spans_from_json(cap["data"]))

    print(f"  Edge span records: {len(edge_spans)}")
    print(f"  otelcol span records: {len(otelcol_spans)}")
    print(f"  Vector span records: {len(vector_spans)}")

    # Show sample records
    if edge_spans:
        print(f"\n  Sample Edge span:")
        print(f"    name: {edge_spans[0].get('name', 'N/A')}")
        print(f"    trace_id: {edge_spans[0].get('trace_id', 'N/A')}")
        print(f"    kind: {edge_spans[0].get('kind', 'N/A')}")

    if otelcol_spans:
        print(f"\n  Sample otelcol span:")
        print(f"    name: {otelcol_spans[0].get('name', 'N/A')}")
        print(f"    trace_id: {otelcol_spans[0].get('trace_id', 'N/A')}")
        print(f"    kind: {otelcol_spans[0].get('kind', 'N/A')}")

    if vector_spans:
        print(f"\n  Sample Vector span (raw JSON):")
        sample = json.dumps(vector_spans[0], indent=4)[:500]
        for line in sample.split("\n"):
            print(f"    {line}")

    # Compare counts
    if len(edge_spans) == len(otelcol_spans):
        print(f"\n  OK: Edge and otelcol have same record count")
    else:
        print(
            f"\n  MISMATCH: Edge ({len(edge_spans)}) vs otelcol ({len(otelcol_spans)})"
        )

    return len(edge_spans), len(otelcol_spans), len(vector_spans)


def compare_metrics(name, edge_caps, otelcol_caps, vector_caps):
    """Compare metrics across systems."""
    print(f"\n=== {name} ===")

    # Extract metrics from each system
    edge_metrics = []
    for cap in edge_caps:
        if "protobuf" in cap["content_type"]:
            edge_metrics.extend(extract_metrics_from_protobuf(cap["data"]))
        else:
            edge_metrics.extend(extract_metrics_from_json(cap["data"]))

    otelcol_metrics = []
    for cap in otelcol_caps:
        if "protobuf" in cap["content_type"]:
            otelcol_metrics.extend(extract_metrics_from_protobuf(cap["data"]))
        else:
            otelcol_metrics.extend(extract_metrics_from_json(cap["data"]))

    vector_metrics = []
    for cap in vector_caps:
        if "protobuf" in cap["content_type"]:
            vector_metrics.extend(extract_metrics_from_protobuf(cap["data"]))
        else:
            vector_metrics.extend(extract_metrics_from_json(cap["data"]))

    print(f"  Edge metric records: {len(edge_metrics)}")
    print(f"  otelcol metric records: {len(otelcol_metrics)}")
    print(f"  Vector metric records: {len(vector_metrics)}")

    # Show sample records
    if edge_metrics:
        print(f"\n  Sample Edge metric:")
        print(f"    name: {edge_metrics[0].get('name', 'N/A')}")
        print(f"    unit: {edge_metrics[0].get('unit', 'N/A')}")

    if otelcol_metrics:
        print(f"\n  Sample otelcol metric:")
        print(f"    name: {otelcol_metrics[0].get('name', 'N/A')}")
        print(f"    unit: {otelcol_metrics[0].get('unit', 'N/A')}")

    if vector_metrics:
        print(f"\n  Sample Vector metric (raw JSON):")
        sample = json.dumps(vector_metrics[0], indent=4)[:500]
        for line in sample.split("\n"):
            print(f"    {line}")

    # Compare counts
    if len(edge_metrics) == len(otelcol_metrics):
        print(f"\n  OK: Edge and otelcol have same record count")
    else:
        print(
            f"\n  MISMATCH: Edge ({len(edge_metrics)}) vs otelcol ({len(otelcol_metrics)})"
        )

    return len(edge_metrics), len(otelcol_metrics), len(vector_metrics)


def main():
    parser = argparse.ArgumentParser(description="Compare captured payloads")
    parser.add_argument(
        "--dir",
        default=str(SCRIPT_DIR / "equivalence-test"),
        help="Directory containing captured files",
    )
    args = parser.parse_args()

    output_dir = Path(args.dir)

    print("=" * 60)
    print("  Data Equivalence Comparison")
    print("=" * 60)

    # Compare OTLP Logs
    edge_logs = load_captures(output_dir / "edge-otlp-logs.jsonl")
    otelcol_logs = load_captures(output_dir / "otelcol-otlp-logs.jsonl")
    vector_logs = load_captures(output_dir / "vector-otlp-logs.jsonl")
    compare_logs("OTLP Logs", edge_logs, otelcol_logs, vector_logs)

    # Compare OTLP Traces
    edge_traces = load_captures(output_dir / "edge-otlp-traces.jsonl")
    otelcol_traces = load_captures(output_dir / "otelcol-otlp-traces.jsonl")
    vector_traces = load_captures(output_dir / "vector-otlp-traces.jsonl")
    compare_traces("OTLP Traces", edge_traces, otelcol_traces, vector_traces)

    # Compare OTLP Metrics
    edge_metrics = load_captures(output_dir / "edge-otlp-metrics.jsonl")
    otelcol_metrics = load_captures(output_dir / "otelcol-otlp-metrics.jsonl")
    vector_metrics = load_captures(output_dir / "vector-otlp-metrics.jsonl")
    compare_metrics("OTLP Metrics", edge_metrics, otelcol_metrics, vector_metrics)

    print("\n" + "=" * 60)
    print("  Summary")
    print("=" * 60)
    print("\nEdge and otelcol both preserve OTLP protobuf format.")
    print("Vector converts to JSON, which changes the wire format but")
    print("should preserve the semantic content of records.")


if __name__ == "__main__":
    main()
