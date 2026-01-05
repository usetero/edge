#!/usr/bin/env bash
#
# Generate policy files for scaling benchmarks
#
# Usage: ./generate-policies.sh <count>
#
# Generates N drop policies for fair comparison across Edge, otelcol, and Vector.
# All systems get the same number of filter/drop rules with identical patterns.
#
set -euo pipefail

COUNT=${1:-0}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/configs/generated"

mkdir -p "$OUTPUT_DIR"

# Patterns that WILL match our test payloads
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

# Generate a random non-matching pattern
random_nomatch() {
    echo "NOMATCH_BENCH_$(printf '%04d' $1)_$(head -c 4 /dev/urandom | xxd -p)"
}

# Generate Tero Edge log policies - all drop policies for fair comparison
generate_edge_log_policies() {
    local count=$1
    local policies=()

    if [[ $count -eq 0 ]]; then
        echo '{"policies": []}'
        return
    fi

    # All drop policies - same patterns as otelcol/vector for fair comparison
    for ((i=0; i<count; i++)); do
        local pattern
        # Cycle through matching patterns, then use non-matching ones
        if ((i < ${#MATCHING_PATTERNS[@]})); then
            pattern="${MATCHING_PATTERNS[$i]}"
        else
            pattern=$(random_nomatch $i)
        fi

        policies+=("$(cat <<EOF
    {
      "id": "drop-$(printf '%04d' $i)",
      "name": "Drop policy $i",
      "log": {
        "match": [{"log_field": "body", "regex": "$pattern"}],
        "keep": "none"
      }
    }
EOF
)")
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

# Generate Tero Edge metric policies - all drop policies for fair comparison
generate_edge_metric_policies() {
    local count=$1
    local policies=()

    if [[ $count -eq 0 ]]; then
        echo '{"policies": []}'
        return
    fi

    # Metric patterns that match our payload (only use app.queue to avoid dropping everything)
    local metric_patterns=("app.queue")

    # All drop policies - same pattern approach as logs
    for ((i=0; i<count; i++)); do
        local pattern
        if ((i < ${#metric_patterns[@]})); then
            pattern="${metric_patterns[$i]}"
        else
            pattern=$(random_nomatch $i)
        fi

        policies+=("$(cat <<EOF
    {
      "id": "metric-drop-$(printf '%04d' $i)",
      "name": "Metric drop policy $i",
      "metric": {
        "match": [{"metric_field": "name", "regex": "$pattern"}],
        "keep": false
      }
    }
EOF
)")
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

# Generate combined policies (logs + metrics)
# For fair comparison, we generate N log policies and N metric policies
# This matches otelcol/vector which get N filter rules each
generate_edge_policies() {
    local count=$1

    if [[ $count -eq 0 ]]; then
        echo '{"policies": []}'
        return
    fi

    # Generate same count for both logs and metrics
    local log_json=$(generate_edge_log_policies $count)
    local metric_json=$(generate_edge_metric_policies $count)

    # Merge the two JSON arrays
    local log_policies=$(echo "$log_json" | jq -c '.policies')
    local metric_policies=$(echo "$metric_json" | jq -c '.policies')

    # Combine
    echo "{\"policies\": $(echo "$log_policies $metric_policies" | jq -s 'add')}"
}

# Generate otelcol config with filter and sampling processors
# Note: otelcol does NOT have a rate limiting processor for logs (only traces)
# We generate the same number of filter rules as Edge policies for fair comparison
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
  batch:
    # Small batch for benchmarking - ensures requests flow through
    send_batch_size: 100
    timeout: 100ms
YAML_HEAD

    local processors="batch"

    if [[ $count -gt 0 ]]; then
        # Generate the same number of filter rules as Edge policies
        # This ensures comparable evaluation overhead
        processors="batch, filter"

        # Filter processor with N rules
        echo ""
        echo "  filter:"
        echo "    error_mode: ignore"
        echo "    logs:"
        echo "      log_record:"

        for ((i=0; i<count; i++)); do
            local pattern
            # Cycle through matching patterns, then use non-matching ones
            if ((i < ${#MATCHING_PATTERNS[@]})); then
                pattern="${MATCHING_PATTERNS[$i]}"
            else
                pattern="NOMATCH_BENCH_$(printf '%04d' $i)"
            fi
            echo "        - 'IsMatch(body, \".*${pattern}.*\")'"
        done
    fi

    cat <<YAML_TAIL

exporters:
  otlphttp:
    endpoint: http://127.0.0.1:9999
    compression: none

service:
  telemetry:
    logs:
      level: error
  pipelines:
    logs/otlp:
      receivers: [otlp]
      processors: [$processors]
      exporters: [otlphttp]
    logs/datadog:
      receivers: [datadog]
      processors: [$processors]
      exporters: [otlphttp]
YAML_TAIL
}

# Generate Vector config with filter, sample, and throttle transforms
# Vector uses:
# - port 4320 for OTLP HTTP (native opentelemetry source, accepts protobuf)
# - port 4321 for Datadog (http_server source with JSON)
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

  datadog_source:
    type: http_server
    address: "127.0.0.1:4321"
    decoding:
      codec: json
    path: "/api/v2/logs"
YAML_HEAD

    if [[ $count -gt 0 ]]; then
        echo ""
        echo "transforms:"

        # Generate filter transforms (same count as Edge policies)
        # Each filter is chained to the previous one
        # Note: opentelemetry source outputs to .logs stream
        local prev_otlp="otel_source.logs"
        local prev_dd="datadog_source"

        for ((i=0; i<count; i++)); do
            local pattern
            # Cycle through matching patterns, then use non-matching ones
            if ((i < ${#MATCHING_PATTERNS[@]})); then
                pattern="${MATCHING_PATTERNS[$i]}"
            else
                pattern="NOMATCH_BENCH_$(printf '%04d' $i)"
            fi

            # OTLP filter - use contains() instead of match() for simpler syntax
            cat <<YAML_FILTER
  filter_otlp_$i:
    type: filter
    inputs:
      - "$prev_otlp"
    condition: '!contains(to_string(.message) ?? "", "$pattern")'
YAML_FILTER
            prev_otlp="filter_otlp_$i"

            # Datadog filter
            cat <<YAML_FILTER
  filter_dd_$i:
    type: filter
    inputs:
      - "$prev_dd"
    condition: '!contains(to_string(.message) ?? "", "$pattern")'
YAML_FILTER
            prev_dd="filter_dd_$i"
        done

        # Sinks connect to final filter transforms (no sample/throttle for fair comparison)
        cat <<YAML_SINKS

sinks:
  otlp_out:
    type: http
    inputs:
      - "$prev_otlp"
    uri: "http://127.0.0.1:9999/v1/logs"
    encoding:
      codec: json
    batch:
      max_bytes: 1048576
      timeout_secs: 1

  datadog_out:
    type: http
    inputs:
      - "$prev_dd"
    uri: "http://127.0.0.1:9999/api/v2/logs"
    encoding:
      codec: json
    batch:
      max_bytes: 1048576
      timeout_secs: 1
YAML_SINKS
    else
        # No transforms - passthrough mode
        cat <<'YAML_SINKS'

sinks:
  otlp_out:
    type: http
    inputs:
      - "otel_source.logs"
    uri: "http://127.0.0.1:9999/v1/logs"
    encoding:
      codec: json
    batch:
      max_bytes: 1048576
      timeout_secs: 1

  datadog_out:
    type: http
    inputs:
      - "datadog_source"
    uri: "http://127.0.0.1:9999/api/v2/logs"
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
        log_drop_policies: [.policies[] | select(.log.keep == "none")] | length,
        metric_drop_policies: [.policies[] | select(.metric.keep == false)] | length
    }' "$OUTPUT_DIR/policies-$COUNT.json"
fi
