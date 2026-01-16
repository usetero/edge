#!/usr/bin/env python3
"""
Generate protobuf OTLP payloads for benchmarking.

This script creates binary protobuf files that match the JSON payloads
used in the scaling benchmarks, enabling proper testing with Vector's
native opentelemetry source.
"""

import os
import sys

# Add the generated proto directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "proto_gen"))

from opentelemetry.proto.collector.logs.v1 import logs_service_pb2
from opentelemetry.proto.collector.metrics.v1 import metrics_service_pb2
from opentelemetry.proto.collector.trace.v1 import trace_service_pb2
from opentelemetry.proto.common.v1 import common_pb2
from opentelemetry.proto.logs.v1 import logs_pb2
from opentelemetry.proto.metrics.v1 import metrics_pb2
from opentelemetry.proto.resource.v1 import resource_pb2
from opentelemetry.proto.trace.v1 import trace_pb2


def create_logs_payload():
    """Create an OTLP logs payload matching otlp-logs.json"""

    request = logs_service_pb2.ExportLogsServiceRequest()

    # Create resource logs
    resource_logs = request.resource_logs.add()

    # Set resource attributes
    resource_logs.resource.attributes.add(
        key="service.name", value=common_pb2.AnyValue(string_value="bench-service")
    )
    resource_logs.resource.attributes.add(
        key="service.version", value=common_pb2.AnyValue(string_value="1.0.0")
    )
    resource_logs.resource.attributes.add(
        key="deployment.environment",
        value=common_pb2.AnyValue(string_value="production"),
    )

    # Create scope logs
    scope_logs = resource_logs.scope_logs.add()
    scope_logs.scope.name = "bench-logger"
    scope_logs.scope.version = "1.0.0"

    # Log records - matching the JSON payload
    log_entries = [
        {
            "time_unix_nano": 1700000000000000000,
            "severity_number": 9,
            "severity_text": "INFO",
            "body": "User authentication successful for user_id=12345",
            "attributes": [
                ("user_id", "12345"),
                ("auth_method", "oauth2"),
            ],
            "trace_id": bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
            "span_id": bytes.fromhex("0102030405060708"),
        },
        {
            "time_unix_nano": 1700000001000000000,
            "severity_number": 9,
            "severity_text": "INFO",
            "body": "Payment processed successfully for order_id=ORD-98765",
            "attributes": [
                ("order_id", "ORD-98765"),
                ("amount", 99.99),
                ("credit_card", "4111-XXXX-XXXX-1234"),
                ("ssn", "123-45-6789"),
            ],
            "trace_id": bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
            "span_id": bytes.fromhex("0102030405060709"),
        },
        {
            "time_unix_nano": 1700000002000000000,
            "severity_number": 5,
            "severity_text": "DEBUG",
            "body": "Cache miss for key user:preferences:12345",
            "attributes": [
                ("cache_key", "user:preferences:12345"),
                ("cache_ttl", 3600),
            ],
            "trace_id": bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
            "span_id": bytes.fromhex("010203040506070a"),
        },
        {
            "time_unix_nano": 1700000003000000000,
            "severity_number": 17,
            "severity_text": "ERROR",
            "body": "Database connection failed: timeout after 30s",
            "attributes": [
                ("db_host", "db-primary.internal"),
                ("error_code", "ETIMEDOUT"),
            ],
            "trace_id": bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
            "span_id": bytes.fromhex("010203040506070b"),
        },
        {
            "time_unix_nano": 1700000004000000000,
            "severity_number": 9,
            "severity_text": "INFO",
            "body": "HTTP request completed: GET /api/users/12345",
            "attributes": [
                ("http_method", "GET"),
                ("http_path", "/api/users/12345"),
                ("http_status", 200),
                ("internal_trace_id", "internal-abc123"),
            ],
            "trace_id": bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
            "span_id": bytes.fromhex("010203040506070c"),
        },
        {
            "time_unix_nano": 1700000005000000000,
            "severity_number": 9,
            "severity_text": "INFO",
            "body": "Cache hit for key session:token:xyz789",
            "attributes": [
                ("cache_key", "session:token:xyz789"),
                ("cache_ttl", 1800),
            ],
            "trace_id": bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
            "span_id": bytes.fromhex("010203040506070d"),
        },
        {
            "time_unix_nano": 1700000006000000000,
            "severity_number": 9,
            "severity_text": "INFO",
            "body": "User login event recorded for analytics",
            "attributes": [
                ("event_type", "login"),
                ("platform", "web"),
            ],
            "trace_id": bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
            "span_id": bytes.fromhex("010203040506070e"),
        },
        {
            "time_unix_nano": 1700000007000000000,
            "severity_number": 5,
            "severity_text": "DEBUG",
            "body": "Request validation passed for endpoint /api/orders",
            "attributes": [
                ("validation_rules", 12),
            ],
            "trace_id": bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
            "span_id": bytes.fromhex("010203040506070f"),
        },
        {
            "time_unix_nano": 1700000008000000000,
            "severity_number": 9,
            "severity_text": "INFO",
            "body": "API call to external service completed successfully",
            "attributes": [
                ("http_method", "POST"),
                ("http_path", "/external/webhook"),
                ("response_time_ms", 245),
            ],
            "trace_id": bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
            "span_id": bytes.fromhex("0102030405060710"),
        },
        {
            "time_unix_nano": 1700000009000000000,
            "severity_number": 9,
            "severity_text": "INFO",
            "body": "Scheduled job completed: daily_report_generation",
            "attributes": [
                ("job_name", "daily_report_generation"),
                ("duration_ms", 5432),
            ],
            "trace_id": bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
            "span_id": bytes.fromhex("0102030405060711"),
        },
    ]

    for entry in log_entries:
        log_record = scope_logs.log_records.add()
        log_record.time_unix_nano = entry["time_unix_nano"]
        log_record.severity_number = entry["severity_number"]
        log_record.severity_text = entry["severity_text"]
        log_record.body.string_value = entry["body"]
        log_record.trace_id = entry["trace_id"]
        log_record.span_id = entry["span_id"]

        for attr_key, attr_val in entry["attributes"]:
            attr = log_record.attributes.add()
            attr.key = attr_key
            if isinstance(attr_val, str):
                attr.value.string_value = attr_val
            elif isinstance(attr_val, int):
                attr.value.int_value = attr_val
            elif isinstance(attr_val, float):
                attr.value.double_value = attr_val

    return request.SerializeToString()


def create_metrics_payload():
    """Create an OTLP metrics payload matching otlp-metrics.json"""

    request = metrics_service_pb2.ExportMetricsServiceRequest()

    # Create resource metrics
    resource_metrics = request.resource_metrics.add()

    # Set resource attributes
    resource_metrics.resource.attributes.add(
        key="service.name", value=common_pb2.AnyValue(string_value="bench-service")
    )
    resource_metrics.resource.attributes.add(
        key="service.version", value=common_pb2.AnyValue(string_value="1.0.0")
    )
    resource_metrics.resource.attributes.add(
        key="deployment.environment",
        value=common_pb2.AnyValue(string_value="production"),
    )

    # Create scope metrics
    scope_metrics = resource_metrics.scope_metrics.add()
    scope_metrics.scope.name = "bench-metrics"
    scope_metrics.scope.version = "1.0.0"

    # Metric definitions
    metrics_data = [
        {
            "name": "http_requests_total",
            "description": "Total HTTP requests",
            "unit": "1",
            "sum": {
                "is_monotonic": True,
                "aggregation_temporality": 2,  # CUMULATIVE
                "data_points": [
                    {
                        "value": 12345,
                        "attributes": [("method", "GET"), ("status", "200")],
                    },
                    {
                        "value": 5432,
                        "attributes": [("method", "POST"), ("status", "201")],
                    },
                    {
                        "value": 123,
                        "attributes": [("method", "GET"), ("status", "404")],
                    },
                ],
            },
        },
        {
            "name": "http_request_duration_seconds",
            "description": "HTTP request duration",
            "unit": "s",
            "histogram": {
                "aggregation_temporality": 2,
                "data_points": [
                    {
                        "count": 1000,
                        "sum": 125.5,
                        "bucket_counts": [100, 200, 300, 250, 100, 50],
                        "explicit_bounds": [0.01, 0.05, 0.1, 0.5, 1.0],
                        "attributes": [("endpoint", "/api/users")],
                    }
                ],
            },
        },
        {
            "name": "system_memory_usage_bytes",
            "description": "System memory usage",
            "unit": "By",
            "gauge": {
                "data_points": [
                    {"value": 1073741824, "attributes": [("host", "web-01")]},
                    {"value": 2147483648, "attributes": [("host", "web-02")]},
                ]
            },
        },
        {
            "name": "cache_hit_ratio",
            "description": "Cache hit ratio",
            "unit": "1",
            "gauge": {
                "data_points": [
                    {"value": 0.85, "attributes": [("cache", "redis")]},
                    {"value": 0.92, "attributes": [("cache", "memcached")]},
                ]
            },
        },
        {
            "name": "payment_amount_dollars",
            "description": "Payment amounts processed",
            "unit": "$",
            "sum": {
                "is_monotonic": True,
                "aggregation_temporality": 2,
                "data_points": [
                    {"value": 99999.99, "attributes": [("currency", "USD")]},
                    {"value": 45678.50, "attributes": [("currency", "EUR")]},
                ],
            },
        },
    ]

    base_time = 1700000000000000000

    for metric_def in metrics_data:
        metric = scope_metrics.metrics.add()
        metric.name = metric_def["name"]
        metric.description = metric_def["description"]
        metric.unit = metric_def["unit"]

        if "sum" in metric_def:
            sum_data = metric_def["sum"]
            metric.sum.is_monotonic = sum_data["is_monotonic"]
            metric.sum.aggregation_temporality = sum_data["aggregation_temporality"]

            for dp_def in sum_data["data_points"]:
                dp = metric.sum.data_points.add()
                dp.time_unix_nano = base_time
                dp.start_time_unix_nano = base_time - 60000000000
                if isinstance(dp_def["value"], float):
                    dp.as_double = dp_def["value"]
                else:
                    dp.as_int = dp_def["value"]

                for attr_key, attr_val in dp_def["attributes"]:
                    attr = dp.attributes.add()
                    attr.key = attr_key
                    attr.value.string_value = str(attr_val)

        elif "gauge" in metric_def:
            gauge_data = metric_def["gauge"]

            for dp_def in gauge_data["data_points"]:
                dp = metric.gauge.data_points.add()
                dp.time_unix_nano = base_time
                if isinstance(dp_def["value"], float):
                    dp.as_double = dp_def["value"]
                else:
                    dp.as_int = dp_def["value"]

                for attr_key, attr_val in dp_def["attributes"]:
                    attr = dp.attributes.add()
                    attr.key = attr_key
                    attr.value.string_value = str(attr_val)

        elif "histogram" in metric_def:
            hist_data = metric_def["histogram"]
            metric.histogram.aggregation_temporality = hist_data[
                "aggregation_temporality"
            ]

            for dp_def in hist_data["data_points"]:
                dp = metric.histogram.data_points.add()
                dp.time_unix_nano = base_time
                dp.start_time_unix_nano = base_time - 60000000000
                dp.count = dp_def["count"]
                dp.sum = dp_def["sum"]
                dp.bucket_counts.extend(dp_def["bucket_counts"])
                dp.explicit_bounds.extend(dp_def["explicit_bounds"])

                for attr_key, attr_val in dp_def["attributes"]:
                    attr = dp.attributes.add()
                    attr.key = attr_key
                    attr.value.string_value = str(attr_val)

    return request.SerializeToString()


def create_traces_payload():
    """Create an OTLP traces payload for benchmarking"""

    request = trace_service_pb2.ExportTraceServiceRequest()

    # Create resource spans
    resource_spans = request.resource_spans.add()

    # Set resource attributes
    resource_spans.resource.attributes.add(
        key="service.name", value=common_pb2.AnyValue(string_value="bench-service")
    )
    resource_spans.resource.attributes.add(
        key="service.version", value=common_pb2.AnyValue(string_value="1.0.0")
    )
    resource_spans.resource.attributes.add(
        key="deployment.environment",
        value=common_pb2.AnyValue(string_value="production"),
    )

    # Create scope spans
    scope_spans = resource_spans.scope_spans.add()
    scope_spans.scope.name = "bench-tracer"
    scope_spans.scope.version = "1.0.0"

    # Base trace ID (16 bytes)
    base_trace_id = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")

    # Span definitions - varied span names and kinds for policy matching
    span_entries = [
        {
            "trace_id": base_trace_id,
            "span_id": bytes.fromhex("0102030405060708"),
            "parent_span_id": b"",
            "name": "HTTP GET /api/users",
            "kind": trace_pb2.Span.SPAN_KIND_SERVER,
            "status_code": trace_pb2.Status.STATUS_CODE_OK,
            "attributes": [
                ("http.method", "GET"),
                ("http.url", "/api/users"),
                ("http.status_code", 200),
                ("peer.service", "api-gateway"),
            ],
        },
        {
            "trace_id": base_trace_id,
            "span_id": bytes.fromhex("0102030405060709"),
            "parent_span_id": bytes.fromhex("0102030405060708"),
            "name": "database query",
            "kind": trace_pb2.Span.SPAN_KIND_CLIENT,
            "status_code": trace_pb2.Status.STATUS_CODE_OK,
            "attributes": [
                ("db.system", "postgresql"),
                ("db.statement", "SELECT * FROM users WHERE id = $1"),
                ("db.name", "users_db"),
                ("peer.service", "postgres"),
            ],
        },
        {
            "trace_id": base_trace_id,
            "span_id": bytes.fromhex("010203040506070a"),
            "parent_span_id": bytes.fromhex("0102030405060708"),
            "name": "cache lookup",
            "kind": trace_pb2.Span.SPAN_KIND_INTERNAL,
            "status_code": trace_pb2.Status.STATUS_CODE_OK,
            "attributes": [
                ("cache.type", "redis"),
                ("cache.hit", True),
            ],
        },
        {
            "trace_id": base_trace_id,
            "span_id": bytes.fromhex("010203040506070b"),
            "parent_span_id": bytes.fromhex("0102030405060708"),
            "name": "HTTP POST /api/orders",
            "kind": trace_pb2.Span.SPAN_KIND_SERVER,
            "status_code": trace_pb2.Status.STATUS_CODE_ERROR,
            "status_message": "Order validation failed",
            "attributes": [
                ("http.method", "POST"),
                ("http.url", "/api/orders"),
                ("http.status_code", 400),
                ("error", True),
            ],
        },
        {
            "trace_id": base_trace_id,
            "span_id": bytes.fromhex("010203040506070c"),
            "parent_span_id": bytes.fromhex("0102030405060708"),
            "name": "message publish",
            "kind": trace_pb2.Span.SPAN_KIND_PRODUCER,
            "status_code": trace_pb2.Status.STATUS_CODE_OK,
            "attributes": [
                ("messaging.system", "kafka"),
                ("messaging.destination", "orders-topic"),
                ("messaging.operation", "publish"),
            ],
        },
        {
            "trace_id": base_trace_id,
            "span_id": bytes.fromhex("010203040506070d"),
            "parent_span_id": bytes.fromhex("0102030405060708"),
            "name": "message consume",
            "kind": trace_pb2.Span.SPAN_KIND_CONSUMER,
            "status_code": trace_pb2.Status.STATUS_CODE_OK,
            "attributes": [
                ("messaging.system", "kafka"),
                ("messaging.destination", "orders-topic"),
                ("messaging.operation", "receive"),
            ],
        },
        {
            "trace_id": base_trace_id,
            "span_id": bytes.fromhex("010203040506070e"),
            "parent_span_id": bytes.fromhex("0102030405060708"),
            "name": "authentication check",
            "kind": trace_pb2.Span.SPAN_KIND_INTERNAL,
            "status_code": trace_pb2.Status.STATUS_CODE_OK,
            "attributes": [
                ("auth.method", "jwt"),
                ("auth.success", True),
                ("user.id", "12345"),
            ],
        },
        {
            "trace_id": base_trace_id,
            "span_id": bytes.fromhex("010203040506070f"),
            "parent_span_id": bytes.fromhex("0102030405060708"),
            "name": "external API call",
            "kind": trace_pb2.Span.SPAN_KIND_CLIENT,
            "status_code": trace_pb2.Status.STATUS_CODE_OK,
            "attributes": [
                ("http.method", "GET"),
                ("http.url", "https://external-api.example.com/data"),
                ("http.status_code", 200),
                ("peer.service", "external-api"),
            ],
        },
        {
            "trace_id": base_trace_id,
            "span_id": bytes.fromhex("0102030405060710"),
            "parent_span_id": bytes.fromhex("0102030405060708"),
            "name": "data processing",
            "kind": trace_pb2.Span.SPAN_KIND_INTERNAL,
            "status_code": trace_pb2.Status.STATUS_CODE_OK,
            "attributes": [
                ("processing.type", "transform"),
                ("processing.items", 100),
            ],
        },
        {
            "trace_id": base_trace_id,
            "span_id": bytes.fromhex("0102030405060711"),
            "parent_span_id": bytes.fromhex("0102030405060708"),
            "name": "response serialization",
            "kind": trace_pb2.Span.SPAN_KIND_INTERNAL,
            "status_code": trace_pb2.Status.STATUS_CODE_OK,
            "attributes": [
                ("serialization.format", "json"),
                ("serialization.bytes", 2048),
            ],
        },
    ]

    base_time = 1700000000000000000

    for i, entry in enumerate(span_entries):
        span = scope_spans.spans.add()
        span.trace_id = entry["trace_id"]
        span.span_id = entry["span_id"]
        if entry["parent_span_id"]:
            span.parent_span_id = entry["parent_span_id"]
        span.name = entry["name"]
        span.kind = entry["kind"]
        span.start_time_unix_nano = base_time + (i * 1000000)  # 1ms apart
        span.end_time_unix_nano = base_time + (i * 1000000) + 500000  # 0.5ms duration

        # Status
        span.status.code = entry["status_code"]
        if "status_message" in entry:
            span.status.message = entry["status_message"]

        # Attributes
        for attr_key, attr_val in entry["attributes"]:
            attr = span.attributes.add()
            attr.key = attr_key
            if isinstance(attr_val, str):
                attr.value.string_value = attr_val
            elif isinstance(attr_val, bool):
                attr.value.bool_value = attr_val
            elif isinstance(attr_val, int):
                attr.value.int_value = attr_val
            elif isinstance(attr_val, float):
                attr.value.double_value = attr_val

    return request.SerializeToString()


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    payloads_dir = os.path.join(script_dir, "payloads")

    # Generate logs payload
    logs_pb = create_logs_payload()
    logs_path = os.path.join(payloads_dir, "otlp-logs.pb")
    with open(logs_path, "wb") as f:
        f.write(logs_pb)
    print(f"Generated {logs_path} ({len(logs_pb)} bytes)")

    # Generate metrics payload
    metrics_pb = create_metrics_payload()
    metrics_path = os.path.join(payloads_dir, "otlp-metrics.pb")
    with open(metrics_path, "wb") as f:
        f.write(metrics_pb)
    print(f"Generated {metrics_path} ({len(metrics_pb)} bytes)")

    # Generate traces payload
    traces_pb = create_traces_payload()
    traces_path = os.path.join(payloads_dir, "otlp-traces.pb")
    with open(traces_path, "wb") as f:
        f.write(traces_pb)
    print(f"Generated {traces_path} ({len(traces_pb)} bytes)")


if __name__ == "__main__":
    main()
