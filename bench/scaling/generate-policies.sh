#!/usr/bin/env bash
#
# Generate policy files for scaling benchmarks
#
# Usage: ./generate-policies.sh <count>
#
# Generates N policies with the following distribution:
#   - 50% log policies (25% drops, 25% transforms)
#   - 50% metric policies (25% drops, 25% transforms)
#
# All systems (Edge, otelcol, Vector) get equivalent rules for fair comparison.
#
set -euo pipefail

COUNT=${1:-0}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/configs/generated"

mkdir -p "$OUTPUT_DIR"

# Patterns that WILL match our test payloads (for logs)
MATCHING_PATTERNS=(
    "authentication"
    "Payment"
    "Cache miss"
    "Cache hit"
    "error"
    "ERROR"
    "debug"
    "DEBUG"
    "HTTP request"
    "API call"
    "login"
)

# Metric patterns that match our payload
METRIC_MATCHING_PATTERNS=(
    "app.queue"
)

# Trace span name patterns that match our payload
TRACE_MATCHING_PATTERNS=(
    "HTTP GET"
    "HTTP POST"
    "database query"
    "cache lookup"
    "message publish"
    "message consume"
    "authentication"
    "external API"
    "data processing"
    "serialization"
)

# Generate a deterministic non-matching pattern (no random for reproducibility)
nomatch_pattern() {
    echo "NOMATCH_BENCH_$(printf '%04d' $1)"
}

# Get a log pattern by index
get_log_pattern() {
    local idx=$1
    if ((idx < ${#MATCHING_PATTERNS[@]})); then
        echo "${MATCHING_PATTERNS[$idx]}"
    else
        nomatch_pattern $idx
    fi
}

# Get a metric pattern by index
get_metric_pattern() {
    local idx=$1
    if ((idx < ${#METRIC_MATCHING_PATTERNS[@]})); then
        echo "${METRIC_MATCHING_PATTERNS[$idx]}"
    else
        nomatch_pattern $idx
    fi
}

# Get a trace pattern by index
get_trace_pattern() {
    local idx=$1
    if ((idx < ${#TRACE_MATCHING_PATTERNS[@]})); then
        echo "${TRACE_MATCHING_PATTERNS[$idx]}"
    else
        nomatch_pattern $idx
    fi
}

# Generate Tero Edge policies with drops and transforms
# Distribution: 34% logs (half drop, half transform), 33% metrics (all drops), 33% traces (sampling)
generate_edge_policies() {
    local count=$1
    local policies=()

    if [[ $count -eq 0 ]]; then
        echo '{"policies": []}'
        return
    fi

    # Split: ~34% logs, ~33% metrics, ~33% traces
    local log_count=$((count / 3))
    local metric_count=$((count / 3))
    local trace_count=$((count - log_count - metric_count))

    # Logs: 50% drops, 50% transforms
    local log_drop_count=$((log_count / 2))
    local log_transform_count=$((log_count - log_drop_count))

    local idx=0

    # Log drop policies
    for ((i=0; i<log_drop_count; i++)); do
        local pattern=$(get_log_pattern $i)
        policies+=("$(cat <<EOF
    {
      "id": "log-drop-$(printf '%04d' $idx)",
      "name": "Log drop policy $idx",
      "log": {
        "match": [{"log_field": "body", "regex": "$pattern"}],
        "keep": "none"
      }
    }
EOF
)")
        ((idx++))
    done

    # Log transform policies (keep all + add attribute)
    for ((i=0; i<log_transform_count; i++)); do
        local pattern=$(nomatch_pattern $((log_drop_count + i)))
        policies+=("$(cat <<EOF
    {
      "id": "log-transform-$(printf '%04d' $idx)",
      "name": "Log transform policy $idx",
      "log": {
        "match": [{"log_field": "body", "regex": "$pattern"}],
        "keep": "all",
        "transform": {
          "add": [{"log_attribute": "bench_processed_$i", "value": "true", "upsert": true}]
        }
      }
    }
EOF
)")
        ((idx++))
    done

    # Metric drop policies (no transform support for metrics yet)
    for ((i=0; i<metric_count; i++)); do
        local pattern=$(get_metric_pattern $i)
        policies+=("$(cat <<EOF
    {
      "id": "metric-drop-$(printf '%04d' $idx)",
      "name": "Metric drop policy $idx",
      "metric": {
        "match": [{"metric_field": "name", "regex": "$pattern"}],
        "keep": false
      }
    }
EOF
)")
        ((idx++))
    done

    # Trace sampling policies - vary sampling percentages
    for ((i=0; i<trace_count; i++)); do
        local pattern=$(get_trace_pattern $i)
        # Cycle through different sampling percentages: 10%, 25%, 50%, 75%, 100%
        local percentages=(10.0 25.0 50.0 75.0 100.0)
        local pct=${percentages[$((i % 5))]}
        policies+=("$(cat <<EOF
    {
      "id": "trace-sample-$(printf '%04d' $idx)",
      "name": "Trace sampling policy $idx",
      "trace": {
        "match": [{"trace_field": "TRACE_FIELD_NAME", "regex": "$pattern"}],
        "keep": {
          "percentage": $pct,
          "mode": "SAMPLING_MODE_HASH_SEED",
          "sampling_precision": 4
        }
      }
    }
EOF
)")
        ((idx++))
    done

    # Output JSON
    echo '{"policies": ['
    local first=true
    for policy in "${policies[@]}"; do
        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo ","
        fi
        echo "$policy"
    done
    echo ']}'
}

# Generate otelcol config with filter and transform processors
# Distribution matches Edge: ~34% log rules (half filter, half transform), ~33% metric drops, ~33% trace sampling
# Note: otelcol transform processor uses OTTL for attribute manipulation
# Note: otelcol uses probabilistic_sampler processor for trace sampling
generate_otelcol_config() {
    local count=$1

    # otelcol uses:
    # - port 4318 for OTLP HTTP (standard port)
    # - port 4319 for Datadog receiver (to avoid conflicts)
    # All pipelines export via otlphttp to echo server for measurement
    cat <<'YAML_HEAD'
receivers:
  otlp:
    protocols:
      http:
        endpoint: 127.0.0.1:4318

  datadog:
    endpoint: 127.0.0.1:4319
    read_timeout: 60s

processors:
  batch: {}
YAML_HEAD

    local log_processors="batch"
    local metric_processors="batch"
    local trace_processors="batch"

    if [[ $count -gt 0 ]]; then
        # Split: ~34% logs, ~33% metrics, ~33% traces
        local log_count=$((count / 3))
        local metric_count=$((count / 3))
        local trace_count=$((count - log_count - metric_count))

        # Logs: half drops, half transforms
        local log_drop_count=$((log_count / 2))
        local log_transform_count=$((log_count - log_drop_count))

        # Build processor lists based on what we actually have
        local log_proc_list="batch"
        local metric_proc_list="batch"
        local trace_proc_list="batch"

        # Filter processor for logs - drop rules (only if we have drops)
        if [[ $log_drop_count -gt 0 ]]; then
            log_proc_list="$log_proc_list, filter/logs"
            echo ""
            echo "  filter/logs:"
            echo "    error_mode: ignore"
            echo "    logs:"
            echo "      log_record:"

            for ((i=0; i<log_drop_count; i++)); do
                local pattern
                if ((i < ${#MATCHING_PATTERNS[@]})); then
                    pattern="${MATCHING_PATTERNS[$i]}"
                else
                    pattern="NOMATCH_BENCH_$(printf '%04d' $i)"
                fi
                echo "        - 'IsMatch(body, \".*${pattern}.*\")'"
            done
        fi

        # Transform processor for logs - add attributes (only if we have transforms)
        if [[ $log_transform_count -gt 0 ]]; then
            log_proc_list="$log_proc_list, transform/logs"
            echo ""
            echo "  transform/logs:"
            echo "    error_mode: ignore"
            echo "    log_statements:"

            for ((i=0; i<log_transform_count; i++)); do
                local pattern="NOMATCH_BENCH_$(printf '%04d' $((log_drop_count + i)))"
                echo "      - context: log"
                echo "        conditions:"
                echo "          - 'IsMatch(body, \".*${pattern}.*\")'"
                echo "        statements:"
                echo "          - 'set(attributes[\"bench_processed_$i\"], \"true\")'"
            done
        fi

        # Filter processor for metrics - drop rules (only if we have metrics)
        if [[ $metric_count -gt 0 ]]; then
            metric_proc_list="$metric_proc_list, filter/metrics"
            echo ""
            echo "  filter/metrics:"
            echo "    error_mode: ignore"
            echo "    metrics:"
            echo "      metric:"

            for ((i=0; i<metric_count; i++)); do
                local pattern
                if ((i < ${#METRIC_MATCHING_PATTERNS[@]})); then
                    pattern="${METRIC_MATCHING_PATTERNS[$i]}"
                else
                    pattern="NOMATCH_BENCH_$(printf '%04d' $i)"
                fi
                echo "        - 'IsMatch(name, \".*${pattern}.*\")'"
            done
        fi

        # Probabilistic sampler for traces (only if we have trace policies)
        # otelcol's probabilistic_sampler applies a single sampling rate to all traces
        # We use the average of our sampling percentages for comparison
        if [[ $trace_count -gt 0 ]]; then
            trace_proc_list="$trace_proc_list, probabilistic_sampler"
            # Use 50% as average sampling rate (matches our 10/25/50/75/100 distribution)
            echo ""
            echo "  probabilistic_sampler:"
            echo "    sampling_percentage: 50"
        fi

        log_processors="$log_proc_list"
        metric_processors="$metric_proc_list"
        trace_processors="$trace_proc_list"
    fi

    cat <<YAML_TAIL

exporters:
  # Use otlphttp with protobuf encoding to match input format
  otlphttp/logs:
    endpoint: http://127.0.0.1:9999
    compression: none
    encoding: proto

  otlphttp/metrics:
    endpoint: http://127.0.0.1:9999
    compression: none
    encoding: proto

  otlphttp/traces:
    endpoint: http://127.0.0.1:9999
    compression: none
    encoding: proto

  # For Datadog input, convert to OTLP protobuf for consistent output format
  # Note: otelcol's datadog exporter requires an API key, so we use otlphttp
  otlphttp/datadog:
    endpoint: http://127.0.0.1:9999
    compression: none
    encoding: proto

service:
  telemetry:
    logs:
      level: error
  pipelines:
    logs/otlp:
      receivers: [otlp]
      processors: [$log_processors]
      exporters: [otlphttp/logs]
    logs/datadog:
      receivers: [datadog]
      processors: [$log_processors]
      exporters: [otlphttp/datadog]
    metrics/otlp:
      receivers: [otlp]
      processors: [$metric_processors]
      exporters: [otlphttp/metrics]
    metrics/datadog:
      receivers: [datadog]
      processors: [$metric_processors]
      exporters: [otlphttp/datadog]
    traces:
      receivers: [otlp]
      processors: [$trace_processors]
      exporters: [otlphttp/traces]
YAML_TAIL
}

# Generate Vector config with filter and remap transforms
# Distribution matches Edge: ~34% log rules (half filter, half remap/transform), ~33% metric drops, ~33% trace sampling
# Vector uses:
# - port 4320 for OTLP HTTP (native opentelemetry source, accepts protobuf)
# - port 4321 for Datadog logs (http_server source with JSON)
# - port 4322 for Datadog metrics (http_server source with JSON)
# Note: Vector uses sample transform for trace sampling (probabilistic sampling)
generate_vector_config() {
    local count=$1
    local data_dir="$SCRIPT_DIR/data"

    # Start with data_dir and sources
    # Using native opentelemetry source for proper OTLP parsing
    cat <<YAML_HEAD
data_dir: "$data_dir"

sources:
  otel_source:
    type: opentelemetry
    grpc:
      address: "127.0.0.1:4317"
    http:
      address: "127.0.0.1:4320"

  datadog_logs_source:
    type: http_server
    address: "127.0.0.1:4321"
    decoding:
      codec: json
    path: "/api/v2/logs"

  datadog_metrics_source:
    type: http_server
    address: "127.0.0.1:4322"
    decoding:
      codec: json
    path: "/api/v2/series"
YAML_HEAD

    if [[ $count -gt 0 ]]; then
        # Split: ~34% logs, ~33% metrics, ~33% traces
        local log_count=$((count / 3))
        local metric_count=$((count / 3))
        local trace_count=$((count - log_count - metric_count))

        # Logs: half drops, half transforms
        local log_drop_count=$((log_count / 2))
        local log_transform_count=$((log_count - log_drop_count))

        echo ""
        echo "transforms:"

        # Generate log filter transforms (drops)
        # Each filter is chained to the previous one
        # Note: opentelemetry source outputs to .logs stream
        local prev_otlp_logs="otel_source.logs"
        local prev_dd_logs="datadog_logs_source"

        for ((i=0; i<log_drop_count; i++)); do
            local pattern
            if ((i < ${#MATCHING_PATTERNS[@]})); then
                pattern="${MATCHING_PATTERNS[$i]}"
            else
                pattern="NOMATCH_BENCH_$(printf '%04d' $i)"
            fi

            # OTLP filter
            cat <<YAML_FILTER
  filter_otlp_log_$i:
    type: filter
    inputs:
      - "$prev_otlp_logs"
    condition: '!contains(to_string(.message) ?? "", "$pattern")'
YAML_FILTER
            prev_otlp_logs="filter_otlp_log_$i"

            # Datadog logs filter
            cat <<YAML_FILTER
  filter_dd_log_$i:
    type: filter
    inputs:
      - "$prev_dd_logs"
    condition: '!contains(to_string(.message) ?? "", "$pattern")'
YAML_FILTER
            prev_dd_logs="filter_dd_log_$i"
        done

        # Generate log remap transforms (add attributes)
        for ((i=0; i<log_transform_count; i++)); do
            local pattern="NOMATCH_BENCH_$(printf '%04d' $((log_drop_count + i)))"
            local remap_idx=$((log_drop_count + i))

            # OTLP remap
            cat <<YAML_REMAP
  remap_otlp_log_$remap_idx:
    type: remap
    inputs:
      - "$prev_otlp_logs"
    source: |
      if contains(to_string(.message) ?? "", "$pattern") {
        .bench_processed_$i = "true"
      }
YAML_REMAP
            prev_otlp_logs="remap_otlp_log_$remap_idx"

            # Datadog logs remap
            cat <<YAML_REMAP
  remap_dd_log_$remap_idx:
    type: remap
    inputs:
      - "$prev_dd_logs"
    source: |
      if contains(to_string(.message) ?? "", "$pattern") {
        .bench_processed_$i = "true"
      }
YAML_REMAP
            prev_dd_logs="remap_dd_log_$remap_idx"
        done

        # Generate metric filter transforms (drops)
        # Note: opentelemetry source outputs metrics to .metrics stream
        local prev_otlp_metrics="otel_source.metrics"
        local prev_dd_metrics="datadog_metrics_source"

        for ((i=0; i<metric_count; i++)); do
            local pattern
            if ((i < ${#METRIC_MATCHING_PATTERNS[@]})); then
                pattern="${METRIC_MATCHING_PATTERNS[$i]}"
            else
                pattern="NOMATCH_BENCH_$(printf '%04d' $i)"
            fi

            # OTLP metrics filter
            cat <<YAML_FILTER
  filter_otlp_metric_$i:
    type: filter
    inputs:
      - "$prev_otlp_metrics"
    condition: '!contains(to_string(.name) ?? "", "$pattern")'
YAML_FILTER
            prev_otlp_metrics="filter_otlp_metric_$i"

            # Datadog metrics filter (uses .metric field for metric name)
            cat <<YAML_FILTER
  filter_dd_metric_$i:
    type: filter
    inputs:
      - "$prev_dd_metrics"
    condition: '!contains(to_string(.metric) ?? "", "$pattern")'
YAML_FILTER
            prev_dd_metrics="filter_dd_metric_$i"
        done

        # Generate trace sampling transforms
        # Note: opentelemetry source outputs traces to .traces stream
        # Vector uses "sample" transform for probabilistic sampling
        local prev_otlp_traces="otel_source.traces"

        if [[ $trace_count -gt 0 ]]; then
            # Vector's sample transform uses a rate (keep 1 in N events)
            # To match our 50% average sampling, use rate: 2 (keep 1 in 2 = 50%)
            cat <<YAML_SAMPLE
  sample_traces:
    type: sample
    inputs:
      - "$prev_otlp_traces"
    rate: 2
YAML_SAMPLE
            prev_otlp_traces="sample_traces"
        fi

        # Sinks connect to final transforms
        # Note: Vector's opentelemetry sink cannot re-encode to OTLP protobuf because
        # the opentelemetry source converts OTLP into Vector's internal event format,
        # losing the original protobuf structure. The sink's codec: otlp expects
        # resourceLogs/resourceMetrics fields that no longer exist.
        # We must use http sink with JSON for all outputs.
        cat <<YAML_SINKS

sinks:
  otlp_logs_out:
    type: http
    inputs:
      - "$prev_otlp_logs"
    uri: "http://127.0.0.1:9999/v1/logs"
    encoding:
      codec: json
    batch:
      max_bytes: 1048576
      timeout_secs: 1

  otlp_metrics_out:
    type: http
    inputs:
      - "$prev_otlp_metrics"
    uri: "http://127.0.0.1:9999/v1/metrics"
    encoding:
      codec: json
    batch:
      max_bytes: 1048576
      timeout_secs: 1

  otlp_traces_out:
    type: http
    inputs:
      - "$prev_otlp_traces"
    uri: "http://127.0.0.1:9999/v1/traces"
    encoding:
      codec: json
    batch:
      max_bytes: 1048576
      timeout_secs: 1

  datadog_logs_out:
    type: http
    inputs:
      - "$prev_dd_logs"
    uri: "http://127.0.0.1:9999/api/v2/logs"
    encoding:
      codec: json
    batch:
      max_bytes: 1048576
      timeout_secs: 1

  datadog_metrics_out:
    type: http
    inputs:
      - "$prev_dd_metrics"
    uri: "http://127.0.0.1:9999/api/v2/series"
    encoding:
      codec: json
    batch:
      max_bytes: 1048576
      timeout_secs: 1
YAML_SINKS
    else
        # No transforms - passthrough mode
        # Vector cannot do OTLP passthrough - must use JSON output
        cat <<'YAML_SINKS'

sinks:
  otlp_logs_out:
    type: http
    inputs:
      - "otel_source.logs"
    uri: "http://127.0.0.1:9999/v1/logs"
    encoding:
      codec: json
    batch:
      max_bytes: 1048576
      timeout_secs: 1

  otlp_metrics_out:
    type: http
    inputs:
      - "otel_source.metrics"
    uri: "http://127.0.0.1:9999/v1/metrics"
    encoding:
      codec: json
    batch:
      max_bytes: 1048576
      timeout_secs: 1

  otlp_traces_out:
    type: http
    inputs:
      - "otel_source.traces"
    uri: "http://127.0.0.1:9999/v1/traces"
    encoding:
      codec: json
    batch:
      max_bytes: 1048576
      timeout_secs: 1

  datadog_logs_out:
    type: http
    inputs:
      - "datadog_logs_source"
    uri: "http://127.0.0.1:9999/api/v2/logs"
    encoding:
      codec: json
    batch:
      max_bytes: 1048576
      timeout_secs: 1

  datadog_metrics_out:
    type: http
    inputs:
      - "datadog_metrics_source"
    uri: "http://127.0.0.1:9999/api/v2/series"
    encoding:
      codec: json
    batch:
      max_bytes: 1048576
      timeout_secs: 1
YAML_SINKS
    fi
}

# Main
echo "Generating $COUNT policies..."

# Generate Edge policies
generate_edge_policies "$COUNT" | jq '.' > "$OUTPUT_DIR/policies-$COUNT.json"

# Generate otelcol config
generate_otelcol_config "$COUNT" > "$OUTPUT_DIR/otelcol-$COUNT.yaml"

# Generate Vector config
generate_vector_config "$COUNT" > "$OUTPUT_DIR/vector-$COUNT.yaml"

echo "Generated:"
echo "  - $OUTPUT_DIR/policies-$COUNT.json"
echo "  - $OUTPUT_DIR/otelcol-$COUNT.yaml"
echo "  - $OUTPUT_DIR/vector-$COUNT.yaml"

# Show summary
if command -v jq &> /dev/null; then
    echo ""
    echo "Edge policy summary:"
    jq '{
        total: .policies | length,
        log_drop: [.policies[] | select(.log.keep == "none")] | length,
        log_transform: [.policies[] | select(.log.keep == "all" and .log.transform != null)] | length,
        metric_drop: [.policies[] | select(.metric.keep == false)] | length,
        trace_sample: [.policies[] | select(.trace != null)] | length
    }' "$OUTPUT_DIR/policies-$COUNT.json"
fi
