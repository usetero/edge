#!/usr/bin/env bash
#
# Generate policy files for scaling benchmarks
#
# Usage: ./generate-policies.sh <count>
#
# Generates policies with the following distribution:
#   - 40% drop policies (mix of matching and non-matching patterns)
#   - 30% keep policies with transforms
#   - 15% percentage sampling (10%, 25%, 50%)
#   - 15% rate limiting (100/s, 500/s, 1000/m)
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

# Generate Tero Edge log policies
generate_edge_log_policies() {
    local count=$1
    local policies=()

    if [[ $count -eq 0 ]]; then
        echo '{"policies": []}'
        return
    fi

    # Calculate distribution
    local drop_count=$((count * 40 / 100))
    local keep_count=$((count * 30 / 100))
    local sample_count=$((count * 15 / 100))
    local rate_count=$((count - drop_count - keep_count - sample_count))

    local idx=0

    # Drop policies (40%) - mix of matching and non-matching
    for ((i=0; i<drop_count; i++)); do
        local pattern
        if ((i % 3 == 0)) && ((i / 3 < ${#MATCHING_PATTERNS[@]})); then
            # Use matching pattern (will actually drop some logs)
            pattern="${MATCHING_PATTERNS[$((i / 3))]}"
        else
            # Use non-matching pattern (tests evaluation overhead)
            pattern=$(random_nomatch $idx)
        fi

        policies+=("$(cat <<EOF
    {
      "id": "drop-$(printf '%04d' $idx)",
      "name": "Drop policy $idx",
      "log": {
        "match": [{"log_field": "body", "regex": "$pattern"}],
        "keep": "none"
      }
    }
EOF
)")
        ((idx++))
    done

    # Keep policies with transforms (30%)
    for ((i=0; i<keep_count; i++)); do
        local pattern
        local transform

        case $((i % 4)) in
            0)
                pattern="payment"
                transform='"redact": [{"log_attribute": "credit_card", "replacement": "[REDACTED]"}, {"log_attribute": "ssn", "replacement": "[REDACTED]"}]'
                ;;
            1)
                pattern="authentication|login"
                transform='"add": [{"log_attribute": "security_category", "value": "auth", "upsert": true}]'
                ;;
            2)
                pattern="HTTP request|API call"
                transform='"rename": [{"from_log_attribute": "http_method", "to": "method", "upsert": true}], "remove": [{"log_attribute": "internal_trace_id"}]'
                ;;
            3)
                pattern=$(random_nomatch $idx)
                transform='"add": [{"log_attribute": "processed", "value": "true", "upsert": true}]'
                ;;
        esac

        policies+=("$(cat <<EOF
    {
      "id": "keep-$(printf '%04d' $idx)",
      "name": "Keep policy $idx",
      "log": {
        "match": [{"log_field": "body", "regex": "$pattern"}],
        "keep": "all",
        "transform": {$transform}
      }
    }
EOF
)")
        ((idx++))
    done

    # Percentage sampling policies (15%)
    local percentages=("10%" "25%" "50%")
    for ((i=0; i<sample_count; i++)); do
        local pattern
        local pct="${percentages[$((i % 3))]}"

        if ((i % 2 == 0)); then
            pattern="Cache"
        else
            pattern=$(random_nomatch $idx)
        fi

        policies+=("$(cat <<EOF
    {
      "id": "sample-$(printf '%04d' $idx)",
      "name": "Sample policy $idx",
      "log": {
        "match": [{"log_field": "body", "regex": "$pattern"}],
        "keep": "$pct"
      }
    }
EOF
)")
        ((idx++))
    done

    # Rate limiting policies (15%)
    local rates=("100/s" "500/s" "1000/m")
    for ((i=0; i<rate_count; i++)); do
        local pattern
        local rate="${rates[$((i % 3))]}"

        if ((i % 2 == 0)); then
            pattern="info|INFO"
        else
            pattern=$(random_nomatch $idx)
        fi

        policies+=("$(cat <<EOF
    {
      "id": "rate-$(printf '%04d' $idx)",
      "name": "Rate limit policy $idx",
      "log": {
        "match": [{"log_field": "body", "regex": "$pattern"}],
        "keep": "$rate"
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

# Generate Tero Edge metric policies
generate_edge_metric_policies() {
    local count=$1
    local policies=()

    if [[ $count -eq 0 ]]; then
        echo '{"policies": []}'
        return
    fi

    # For metrics, we use a simpler distribution: 50% drop, 50% keep
    local drop_count=$((count / 2))
    local keep_count=$((count - drop_count))

    local idx=0

    # Matching metric patterns
    local metric_patterns=("payment" "auth" "cache" "error" "http" "db" "system")

    # Drop policies
    for ((i=0; i<drop_count; i++)); do
        local pattern
        if ((i < ${#metric_patterns[@]})); then
            pattern="${metric_patterns[$i]}"
        else
            pattern=$(random_nomatch $idx)
        fi

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

    # Keep policies
    for ((i=0; i<keep_count; i++)); do
        local pattern=$(random_nomatch $idx)

        policies+=("$(cat <<EOF
    {
      "id": "metric-keep-$(printf '%04d' $idx)",
      "name": "Metric keep policy $idx",
      "metric": {
        "match": [{"metric_field": "name", "regex": "$pattern"}],
        "keep": true
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

# Generate combined policies (logs + metrics)
generate_edge_policies() {
    local count=$1

    if [[ $count -eq 0 ]]; then
        echo '{"policies": []}'
        return
    fi

    # Split count between logs and metrics (70% logs, 30% metrics)
    local log_count=$((count * 70 / 100))
    local metric_count=$((count - log_count))

    # Generate log policies
    local log_json=$(generate_edge_log_policies $log_count)
    local metric_json=$(generate_edge_metric_policies $metric_count)

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
# - port 4320 for OTLP (http_server source)
# - port 4321 for Datadog (http_server source)
generate_vector_config() {
    local count=$1
    local data_dir="$SCRIPT_DIR/data"

    # Start with data_dir and sources
    cat <<YAML_HEAD
data_dir: "$data_dir"

sources:
  otlp_source:
    type: http_server
    address: "127.0.0.1:4320"
    decoding:
      codec: json
    path: "/v1/logs"

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
        local prev_otlp="otlp_source"
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

        # Add sample transform (simulating percentage sampling)
        cat <<YAML_SAMPLE
  sample_otlp:
    type: sample
    inputs:
      - "$prev_otlp"
    rate: 4

  sample_dd:
    type: sample
    inputs:
      - "$prev_dd"
    rate: 4
YAML_SAMPLE

        # Add throttle transform (simulating rate limiting)
        cat <<YAML_THROTTLE
  throttle_otlp:
    type: throttle
    inputs:
      - "sample_otlp"
    threshold: 10000
    window_secs: 1

  throttle_dd:
    type: throttle
    inputs:
      - "sample_dd"
    threshold: 10000
    window_secs: 1
YAML_THROTTLE

        # Sinks connect to final transforms
        cat <<'YAML_SINKS'

sinks:
  otlp_out:
    type: http
    inputs:
      - "throttle_otlp"
    uri: "http://127.0.0.1:9999/v1/logs"
    encoding:
      codec: json
    batch:
      max_bytes: 1048576
      timeout_secs: 1

  datadog_out:
    type: http
    inputs:
      - "throttle_dd"
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
      - "otlp_source"
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
        log_policies: [.policies[] | select(.log != null)] | length,
        metric_policies: [.policies[] | select(.metric != null)] | length,
        drop_policies: [.policies[] | select(.log.keep == "none" or .metric.keep == false)] | length,
        keep_policies: [.policies[] | select(.log.keep == "all" or .metric.keep == true)] | length,
        sample_policies: [.policies[] | select(.log.keep != null and (.log.keep | test("^[0-9]+%$")))] | length,
        rate_policies: [.policies[] | select(.log.keep != null and (.log.keep | test("/[sm]$")))] | length
    }' "$OUTPUT_DIR/policies-$COUNT.json"
fi
