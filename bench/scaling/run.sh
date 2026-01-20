#!/usr/bin/env bash
#
# Policy Scaling Benchmark - Edge + otelcol (Phase 1 & 2)
#
# Usage: ./bench/scaling/run.sh [OPTIONS]
#
# Options:
#   -n, --requests NUM    Number of requests per test (default: 10000)
#   -c, --connections NUM Number of concurrent connections (default: 50)
#   --skip-build          Skip building binaries
#   --edge-only           Only run Edge benchmarks
#   --otelcol-only        Only run otelcol benchmarks
#   --vector-only         Only run Vector benchmarks
#   --debug               Save server logs
#   -h, --help            Show this help message
#
set -euo pipefail

# Configuration
REQUESTS=10000
CONNECTIONS=50
SKIP_BUILD=false
DEBUG_MODE=false
RUN_EDGE=true
RUN_OTELCOL=true
RUN_VECTOR=true

# For initial testing, only test 0 and 10 policies
# POLICY_COUNTS=(0 10)
# Full test:
POLICY_COUNTS=(0 1 5 10 50 100 500 1000 2000 4000)
# Quick 1000 test:
# POLICY_COUNTS=(0 1000)

# otelcol and vector binary locations
OTELCOL_BIN=""
VECTOR_BIN=""

# Ports
ECHO_SERVER_PORT=9999
DATADOG_PORT=8080
OTLP_PORT=8081

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/results"
DEBUG_DIR="$SCRIPT_DIR/debug"
PAYLOADS_DIR="$SCRIPT_DIR/payloads"
CONFIGS_DIR="$SCRIPT_DIR/configs"

# PIDs for cleanup
ECHO_PID=""
VECTOR_PID=""
EDGE_PID=""
OTELCOL_PID=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Find otelcol-contrib binary
find_otelcol() {
    # Check in bench/bin first
    if [[ -x "$PROJECT_ROOT/bench/bin/otelcol-contrib" ]]; then
        echo "$PROJECT_ROOT/bench/bin/otelcol-contrib"
        return
    fi
    # Check in PATH
    if command -v otelcol-contrib >/dev/null 2>&1; then
        command -v otelcol-contrib
        return
    fi
    # Not found
    echo ""
}

# Find vector binary
find_vector() {
    # Check in bench/bin first
    if [[ -x "$PROJECT_ROOT/bench/bin/vector" ]]; then
        echo "$PROJECT_ROOT/bench/bin/vector"
        return
    fi
    # Check in PATH
    if command -v vector >/dev/null 2>&1; then
        command -v vector
        return
    fi
    # Not found
    echo ""
}

# Start otelcol
start_otelcol() {
    local config=$1
    local scenario_name=$2
    local wait_port=$3

    # Kill existing if running
    [[ -n "$OTELCOL_PID" ]] && kill "$OTELCOL_PID" 2>/dev/null && sleep 0.3 || true
    OTELCOL_PID=""

    log_info "Starting otelcol-contrib..."

    if [[ "$DEBUG_MODE" == "true" ]]; then
        local log_file="$DEBUG_DIR/otelcol-$(echo "$scenario_name" | tr ' ' '-').log"
        "$OTELCOL_BIN" --config "$config" > "$log_file" 2>&1 &
    else
        "$OTELCOL_BIN" --config "$config" >/dev/null 2>&1 &
    fi
    OTELCOL_PID=$!
    wait_for_server "$wait_port" "otelcol"
}

# Stop otelcol
stop_otelcol() {
    if [[ -n "$OTELCOL_PID" ]]; then
        kill "$OTELCOL_PID" 2>/dev/null || true
        wait "$OTELCOL_PID" 2>/dev/null || true
        OTELCOL_PID=""
    fi
}

# Start Vector
start_vector() {
    local config=$1
    local scenario_name=$2
    local wait_port=$3

    # Stop any existing vector first
    stop_vector

    # Create data directory for Vector
    mkdir -p "$SCRIPT_DIR/data"

    log_info "Starting vector..."

    if [[ "$DEBUG_MODE" == "true" ]]; then
        local log_file="$DEBUG_DIR/vector-$(echo "$scenario_name" | tr ' ' '-').log"
        "$VECTOR_BIN" --config "$config" > "$log_file" 2>&1 &
    else
        "$VECTOR_BIN" --config "$config" >/dev/null 2>&1 &
    fi
    VECTOR_PID=$!
    # Vector with many policies may take longer to start
    wait_for_server "$wait_port" "vector" 120
}

# Stop Vector
stop_vector() {
    if [[ -n "$VECTOR_PID" ]]; then
        # Give Vector time to flush buffers before stopping
        sleep 2
        kill "$VECTOR_PID" 2>/dev/null || true
        # Wait for graceful shutdown
        for i in {1..20}; do
            kill -0 "$VECTOR_PID" 2>/dev/null || break
            sleep 0.3
        done
        # Force kill if still running
        kill -9 "$VECTOR_PID" 2>/dev/null || true
        sleep 0.3
        VECTOR_PID=""
    fi
}

cleanup() {
    log_info "Cleaning up..."
    # Kill by PID first
    [[ -n "$ECHO_PID" ]] && kill -9 "$ECHO_PID" 2>/dev/null || true
    [[ -n "$EDGE_PID" ]] && kill -9 "$EDGE_PID" 2>/dev/null || true
    [[ -n "$OTELCOL_PID" ]] && kill -9 "$OTELCOL_PID" 2>/dev/null || true
    [[ -n "$VECTOR_PID" ]] && kill -9 "$VECTOR_PID" 2>/dev/null || true
    # Then pkill to catch any orphans
    pkill -9 -f "echo-server" 2>/dev/null || true
    pkill -9 -f "edge-otlp" 2>/dev/null || true
    pkill -9 -f "edge-datadog" 2>/dev/null || true
    pkill -9 -f "otelcol" 2>/dev/null || true
    pkill -9 -f "vector.*--config" 2>/dev/null || true
    sleep 0.5
}

trap cleanup EXIT INT TERM

usage() {
    sed -n '3,13p' "$0" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

check_dependencies() {
    local missing=()
    command -v oha >/dev/null 2>&1 || missing+=("oha")
    command -v curl >/dev/null 2>&1 || missing+=("curl")
    command -v jq >/dev/null 2>&1 || missing+=("jq")

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing[*]}"
        echo "Install with: brew install oha jq"
        exit 1
    fi

    # Check for otelcol if needed
    if [[ "$RUN_OTELCOL" == "true" ]]; then
        OTELCOL_BIN=$(find_otelcol)
        if [[ -z "$OTELCOL_BIN" ]]; then
            log_warn "otelcol-contrib not found, skipping otelcol benchmarks"
            log_warn "Install to bench/bin/otelcol-contrib or add to PATH"
            RUN_OTELCOL=false
        else
            log_success "Found otelcol: $OTELCOL_BIN"
        fi
    fi

    # Check for vector if needed
    if [[ "$RUN_VECTOR" == "true" ]]; then
        VECTOR_BIN=$(find_vector)
        if [[ -z "$VECTOR_BIN" ]]; then
            log_warn "vector not found, skipping Vector benchmarks"
            log_warn "Install to bench/bin/vector or add to PATH"
            RUN_VECTOR=false
        else
            log_success "Found vector: $VECTOR_BIN"
        fi
    fi

    log_success "All dependencies found"
}

wait_for_server() {
    local port=$1
    local name=$2
    local max_attempts=${3:-60}  # Default 60 attempts = 6 seconds
    local attempt=0

    while ! curl -s --max-time 1 "http://127.0.0.1:$port" >/dev/null 2>&1; do
        attempt=$((attempt + 1))
        if [[ $attempt -ge $max_attempts ]]; then
            log_error "$name failed to start on port $port"
            return 1
        fi
        sleep 0.1
    done
    log_success "$name ready on port $port"
}

start_echo_server() {
    log_info "Starting echo server..."
    if [[ "$DEBUG_MODE" == "true" ]]; then
        "$PROJECT_ROOT/zig-out/bin/echo-server" "$ECHO_SERVER_PORT" > "$DEBUG_DIR/echo-server.log" 2>&1 &
    else
        "$PROJECT_ROOT/zig-out/bin/echo-server" "$ECHO_SERVER_PORT" >/dev/null 2>&1 &
    fi
    ECHO_PID=$!
    wait_for_server "$ECHO_SERVER_PORT" "Echo server"
}

reset_echo_stats() {
    curl -s -X POST "http://127.0.0.1:$ECHO_SERVER_PORT/reset" >/dev/null
}

get_echo_stats() {
    curl -s "http://127.0.0.1:$ECHO_SERVER_PORT/stats"
}

start_edge_proxy() {
    local binary=$1
    local config=$2
    local port=$3
    local scenario_name=$4

    # Kill existing if running
    [[ -n "$EDGE_PID" ]] && kill "$EDGE_PID" 2>/dev/null && sleep 0.3 || true
    EDGE_PID=""

    log_info "Starting $binary..."

    if [[ "$DEBUG_MODE" == "true" ]]; then
        local log_file="$DEBUG_DIR/${binary}-$(echo "$scenario_name" | tr ' ' '-').log"
        "$PROJECT_ROOT/zig-out/bin/$binary" "$config" > "$log_file" 2>&1 &
    else
        "$PROJECT_ROOT/zig-out/bin/$binary" "$config" >/dev/null 2>&1 &
    fi
    EDGE_PID=$!
    wait_for_server "$port" "$binary"
}

# Resource monitoring (simplified from bench/run.sh)
MONITOR_PID=""
RESOURCE_FILE=""
CPU_START_TIME=""
BENCH_START_WALL=""
MONITORED_PID=""

get_cpu_seconds() {
    local pid=$1
    local time_str
    time_str=$(ps -o time= -p "$pid" 2>/dev/null | tr -d ' ')
    [[ -z "$time_str" ]] && echo "0" && return
    echo "$time_str" | awk -F: '{
        n = NF; secs = $n + 0
        if (n == 2) { printf "%.2f", $1 * 60 + secs }
        else if (n == 3) { printf "%.2f", $1 * 3600 + $2 * 60 + secs }
        else { printf "%.2f", secs }
    }'
}

start_resource_monitor() {
    local target_pid=$1
    MONITORED_PID="$target_pid"
    RESOURCE_FILE=$(mktemp /tmp/bench_mem_XXXXXX)
    CPU_START_TIME=$(get_cpu_seconds "$target_pid")
    BENCH_START_WALL=$(date +%s.%N)

    (
        trap '' TERM INT
        while kill -0 "$target_pid" 2>/dev/null; do
            ps -o rss= -p "$target_pid" 2>/dev/null | tr -d ' ' >> "$RESOURCE_FILE"
            sleep 0.1
        done
    ) 2>/dev/null &
    MONITOR_PID=$!
    disown "$MONITOR_PID" 2>/dev/null || true
}

stop_resource_monitor() {
    local target_pid="$MONITORED_PID"
    local cpu_end_time=$(get_cpu_seconds "$target_pid")
    local wall_end=$(date +%s.%N)

    [[ -n "$MONITOR_PID" ]] && kill "$MONITOR_PID" 2>/dev/null || true
    wait "$MONITOR_PID" 2>/dev/null || true
    MONITOR_PID=""

    local cpu_used=$(echo "$cpu_end_time - $CPU_START_TIME" | bc 2>/dev/null || echo "0")
    local wall_time=$(echo "$wall_end - $BENCH_START_WALL" | bc 2>/dev/null || echo "1")
    local cpu_percent=0
    if (( $(echo "$wall_time > 0" | bc -l 2>/dev/null || echo "0") )); then
        cpu_percent=$(echo "scale=1; $cpu_used / $wall_time * 100" | bc 2>/dev/null || echo "0")
    fi

    local peak_mem_mb=0
    if [[ -f "$RESOURCE_FILE" ]] && [[ -s "$RESOURCE_FILE" ]]; then
        local peak_kb=$(sort -n "$RESOURCE_FILE" | tail -1)
        if [[ -n "$peak_kb" ]] && [[ "$peak_kb" =~ ^[0-9]+$ ]]; then
            peak_mem_mb=$(echo "scale=1; $peak_kb / 1024" | bc 2>/dev/null || echo "0")
        fi
    fi

    rm -f "$RESOURCE_FILE" 2>/dev/null
    echo "${cpu_percent},${peak_mem_mb}"
}

run_benchmark() {
    local url=$1
    local payload_file=$2
    local output_file=$3
    local content_type="${4:-application/json}"

    # Run oha with the payload file
    # For binary files (protobuf), we use -D to read from file
    # For JSON, we also use -D for consistency
    oha -n "$REQUESTS" \
        -c "$CONNECTIONS" \
        -m POST \
        -H "Content-Type: $content_type" \
        -D "$payload_file" \
        --output-format json \
        "$url" > "$output_file" 2>/dev/null
}

extract_metrics() {
    local json_file=$1
    [[ ! -f "$json_file" ]] && echo "N/A,N/A,N/A,N/A" && return

    jq -r '
        .statusCodeDistribution as $dist |
        ($dist | to_entries | map(.value) | add // 0) as $total |
        ($dist | to_entries | map(select(.key | test("^2"))) | map(.value) | add // 0) as $success |
        (if $total > 0 then ($success / $total * 100 | floor) else 0 end) as $success_pct |
        [
            (.summary.requestsPerSec | floor),
            (.latencyPercentiles.p50 * 1000 | . * 100 | floor | . / 100),
            (.latencyPercentiles.p99 * 1000 | . * 100 | floor | . / 100),
            $success_pct
        ] | @csv
    ' "$json_file" | tr -d '"'
}

create_edge_config() {
    local binary=$1
    local policy_count=$2
    local config_file="$CONFIGS_DIR/generated/${binary}-${policy_count}.json"
    local policy_file="$CONFIGS_DIR/generated/policies-${policy_count}.json"

    local port
    if [[ "$binary" == "edge-datadog" ]]; then
        port=$DATADOG_PORT
    else
        port=$OTLP_PORT
    fi

    cat > "$config_file" <<EOF
{
  "listen_address": "127.0.0.1",
  "listen_port": $port,
  "worker_count": 4,
  "upstream_url": "http://127.0.0.1:$ECHO_SERVER_PORT",
  "workspace_id": "benchmark",
  "log_level": "err",
  "max_body_size": 4194304,
  "max_upstream_retries": 10,
  "policy_providers": [
    {
      "id": "bench-policies",
      "type": "file",
      "path": "$policy_file"
    }
  ]
}
EOF
    echo "$config_file"
}

verify_request_count() {
    local expected_requests=$1
    local stats=$2
    local scenario=$3

    local total_requests=$(echo "$stats" | jq -r '.total_requests')

    # Allow 5% variance for sampling/rate limiting effects
    local min_expected=$((expected_requests * 85 / 100))
    local max_expected=$((expected_requests * 105 / 100))

    if [[ "$total_requests" -lt "$min_expected" ]] || [[ "$total_requests" -gt "$max_expected" ]]; then
        log_warn "Unexpected request count for $scenario: got $total_requests, expected ~$expected_requests"
        return 1
    fi
    return 0
}

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--requests) REQUESTS="$2"; shift 2 ;;
            -c|--connections) CONNECTIONS="$2"; shift 2 ;;
            --skip-build) SKIP_BUILD=true; shift ;;
            --debug) DEBUG_MODE=true; shift ;;
            --edge-only) RUN_EDGE=true; RUN_OTELCOL=false; RUN_VECTOR=false; shift ;;
            --otelcol-only) RUN_EDGE=false; RUN_OTELCOL=true; RUN_VECTOR=false; shift ;;
            --vector-only) RUN_EDGE=false; RUN_OTELCOL=false; RUN_VECTOR=true; shift ;;
            -h|--help) usage ;;
            *) log_error "Unknown option: $1"; usage ;;
        esac
    done

    # Determine what we're running for title
    local run_what=""
    local components=()
    [[ "$RUN_EDGE" == "true" ]] && components+=("Edge")
    [[ "$RUN_OTELCOL" == "true" ]] && components+=("otelcol")
    [[ "$RUN_VECTOR" == "true" ]] && components+=("Vector")
    run_what=$(IFS=" + "; echo "${components[*]}")

    echo ""
    echo "=========================================="
    echo "  Policy Scaling Benchmark - $run_what"
    echo "=========================================="
    echo ""

    cd "$PROJECT_ROOT"

    check_dependencies
    mkdir -p "$OUTPUT_DIR" "$CONFIGS_DIR/generated"
    [[ "$DEBUG_MODE" == "true" ]] && mkdir -p "$DEBUG_DIR"

    # Build if needed
    if [[ "$SKIP_BUILD" == "false" ]]; then
        log_info "Building release binaries..."
        zig build echo-server datadog otlp -Doptimize=ReleaseFast
        log_success "Build complete"
    fi

    # Generate protobuf payloads for OTLP tests (used by Edge, otelcol, and Vector)
    if [[ "$RUN_EDGE" == "true" ]] || [[ "$RUN_OTELCOL" == "true" ]] || [[ "$RUN_VECTOR" == "true" ]]; then
        log_info "Generating protobuf OTLP payloads..."
        python3 "$SCRIPT_DIR/generate-protobuf-payloads.py"
        log_success "Protobuf payloads generated"
    fi

    # Start echo server
    start_echo_server

    # CSV header
    local results_file="$OUTPUT_DIR/results.csv"
    echo "binary,telemetry_type,policy_count,payload_bytes,rps,p50_ms,p99_ms,success_pct,cpu_pct,mem_mb,echo_requests,echo_bytes" > "$results_file"

    echo ""
    log_info "Running benchmarks: $REQUESTS requests, $CONNECTIONS connections"
    log_info "Policy counts: ${POLICY_COUNTS[*]}"
    echo ""

    for count in "${POLICY_COUNTS[@]}"; do
        echo ""
        log_info "=== Testing with $count policies ==="

        # Generate policies
        "$SCRIPT_DIR/generate-policies.sh" "$count" >/dev/null

        # ========== Edge Benchmarks ==========
        if [[ "$RUN_EDGE" == "true" ]]; then
            # Format: binary|name|port|endpoint|payload|content_type
            local edge_scenarios=(
                "edge-otlp|OTLP Logs|$OTLP_PORT|/v1/logs|$PAYLOADS_DIR/otlp-logs.pb|application/x-protobuf"
                "edge-otlp|OTLP Metrics|$OTLP_PORT|/v1/metrics|$PAYLOADS_DIR/otlp-metrics.pb|application/x-protobuf"
                # "edge-otlp|OTLP Traces|$OTLP_PORT|/v1/traces|$PAYLOADS_DIR/otlp-traces.pb|application/x-protobuf"
                "edge-datadog|DD Logs|$DATADOG_PORT|/api/v2/logs|$PAYLOADS_DIR/datadog-logs.json|application/json"
                "edge-datadog|DD Metrics|$DATADOG_PORT|/api/v2/series|$PAYLOADS_DIR/datadog-metrics.json|application/json"
            )

            for scenario in "${edge_scenarios[@]}"; do
                IFS='|' read -r binary name port endpoint payload content_type <<< "$scenario"

                local payload_size=$(wc -c < "$payload" | tr -d ' ')
                local config=$(create_edge_config "$binary" "$count")
                local output_json="$OUTPUT_DIR/${binary}-${name// /-}-${count}.json"
                local url="http://127.0.0.1:$port$endpoint"

                # Start edge proxy with this config
                start_edge_proxy "$binary" "$config" "$port" "${name}-${count}"

                # Reset echo server stats
                reset_echo_stats

                # Start resource monitoring
                start_resource_monitor "$EDGE_PID"

                # Run benchmark
                log_info "Running: $name ($binary, $count policies)..."
                run_benchmark "$url" "$payload" "$output_json" "$content_type"

                # Stop monitoring
                local resource_metrics=$(stop_resource_monitor)

                # Get echo server stats
                local echo_stats=$(get_echo_stats)
                local echo_requests=$(echo "$echo_stats" | jq -r '.total_requests')
                local echo_bytes=$(echo "$echo_stats" | jq -r '.total_bytes')

                # Extract benchmark metrics
                local metrics=$(extract_metrics "$output_json")
                IFS=',' read -r rps p50 p99 success <<< "$metrics"
                IFS=',' read -r cpu_percent peak_mem <<< "$resource_metrics"

                # Verify request count (for passthrough, should be ~100%)
                if [[ "$count" -eq 0 ]]; then
                    verify_request_count "$REQUESTS" "$echo_stats" "$name" || true
                fi

                # Log results
                local success_color="${GREEN}"
                [[ "$success" != "100" ]] && success_color="${RED}"

                log_success "$name: ${rps} req/s, p50: ${p50}ms, p99: ${p99}ms, success: ${success_color}${success}%${NC}, echo: ${echo_requests} reqs"

                # Write to CSV
                echo "$binary,$name,$count,$payload_size,$rps,$p50,$p99,$success,$cpu_percent,$peak_mem,$echo_requests,$echo_bytes" >> "$results_file"
            done
        fi

        # ========== otelcol Benchmarks ==========
        if [[ "$RUN_OTELCOL" == "true" ]]; then
            # otelcol scenarios: OTLP Logs, Metrics, Traces, DD Logs
            # Uses filter processor for logs/metrics and probabilistic_sampler for traces
            local otelcol_config="$CONFIGS_DIR/generated/otelcol-${count}.yaml"

            # otelcol scenarios:
            # - OTLP HTTP on port 4318 (protobuf)
            # - Datadog receiver on port 4319 (JSON)
            # Format: binary|name|port|endpoint|payload|content_type
            local otelcol_scenarios=(
                "otelcol|OTLP Logs|4318|/v1/logs|$PAYLOADS_DIR/otlp-logs.pb|application/x-protobuf"
                "otelcol|OTLP Metrics|4318|/v1/metrics|$PAYLOADS_DIR/otlp-metrics.pb|application/x-protobuf"
                # "otelcol|OTLP Traces|4318|/v1/traces|$PAYLOADS_DIR/otlp-traces.pb|application/x-protobuf"
                "otelcol|DD Logs|4319|/api/v2/logs|$PAYLOADS_DIR/datadog-logs.json|application/json"
                # DD Metrics disabled - otelcol datadog receiver has issues with /api/v1/series format
            )

            for scenario in "${otelcol_scenarios[@]}"; do
                IFS='|' read -r binary name port endpoint payload content_type <<< "$scenario"

                local payload_size=$(wc -c < "$payload" | tr -d ' ')
                local output_json="$OUTPUT_DIR/${binary}-${name// /-}-${count}.json"
                local url="http://127.0.0.1:$port$endpoint"

                # Start otelcol with this config, wait for the specific port
                start_otelcol "$otelcol_config" "${name}-${count}" "$port"

                # Reset echo server stats
                reset_echo_stats

                # Start resource monitoring
                start_resource_monitor "$OTELCOL_PID"

                # Run benchmark
                log_info "Running: $name ($binary, $count policies)..."
                run_benchmark "$url" "$payload" "$output_json" "$content_type"

                # Stop monitoring
                local resource_metrics=$(stop_resource_monitor)

                # Stop otelcol between tests
                stop_otelcol

                # Get echo server stats
                local echo_stats=$(get_echo_stats)
                local echo_requests=$(echo "$echo_stats" | jq -r '.total_requests')
                local echo_bytes=$(echo "$echo_stats" | jq -r '.total_bytes')

                # Extract benchmark metrics
                local metrics=$(extract_metrics "$output_json")
                IFS=',' read -r rps p50 p99 success <<< "$metrics"
                IFS=',' read -r cpu_percent peak_mem <<< "$resource_metrics"

                # Verify request count (for passthrough, should be ~100%)
                if [[ "$count" -eq 0 ]]; then
                    verify_request_count "$REQUESTS" "$echo_stats" "$name" || true
                fi

                # Log results
                local success_color="${GREEN}"
                [[ "$success" != "100" ]] && success_color="${RED}"

                log_success "$name: ${rps} req/s, p50: ${p50}ms, p99: ${p99}ms, success: ${success_color}${success}%${NC}, echo: ${echo_requests} reqs"

                # Write to CSV
                echo "$binary,$name,$count,$payload_size,$rps,$p50,$p99,$success,$cpu_percent,$peak_mem,$echo_requests,$echo_bytes" >> "$results_file"
            done
        fi

        # ========== Vector Benchmarks ==========
        if [[ "$RUN_VECTOR" == "true" ]]; then
            local vector_config="$CONFIGS_DIR/generated/vector-${count}.yaml"

            # Vector scenarios:
            # - OTLP HTTP on port 4320 (native opentelemetry source, protobuf)
            # - Datadog HTTP on port 4321 (http_server source, JSON)
            # Uses filter transform for logs/metrics and sample transform for traces
            # Format: binary|name|port|endpoint|payload|content_type
            local vector_scenarios=(
                "vector|OTLP Logs|4320|/v1/logs|$PAYLOADS_DIR/otlp-logs.pb|application/x-protobuf"
                "vector|OTLP Metrics|4320|/v1/metrics|$PAYLOADS_DIR/otlp-metrics.pb|application/x-protobuf"
                # "vector|OTLP Traces|4320|/v1/traces|$PAYLOADS_DIR/otlp-traces.pb|application/x-protobuf"
                "vector|DD Logs|4321|/api/v2/logs|$PAYLOADS_DIR/datadog-logs.json|application/json"
                "vector|DD Metrics|4322|/api/v2/series|$PAYLOADS_DIR/datadog-metrics.json|application/json"
            )

            for scenario in "${vector_scenarios[@]}"; do
                IFS='|' read -r binary name port endpoint payload content_type <<< "$scenario"

                local payload_size=$(wc -c < "$payload" | tr -d ' ')
                local output_json="$OUTPUT_DIR/${binary}-${name// /-}-${count}.json"
                local url="http://127.0.0.1:$port$endpoint"

                # Start vector with this config, wait for the specific port
                start_vector "$vector_config" "${name}-${count}" "$port"

                # Reset echo server stats
                reset_echo_stats

                # Start resource monitoring
                start_resource_monitor "$VECTOR_PID"

                # Run benchmark
                log_info "Running: $name ($binary, $count policies)..."
                run_benchmark "$url" "$payload" "$output_json" "$content_type"

                # Stop monitoring
                local resource_metrics=$(stop_resource_monitor)

                # Stop vector between tests
                stop_vector

                # Get echo server stats
                local echo_stats=$(get_echo_stats)
                local echo_requests=$(echo "$echo_stats" | jq -r '.total_requests')
                local echo_bytes=$(echo "$echo_stats" | jq -r '.total_bytes')

                # Extract benchmark metrics
                local metrics=$(extract_metrics "$output_json")
                IFS=',' read -r rps p50 p99 success <<< "$metrics"
                IFS=',' read -r cpu_percent peak_mem <<< "$resource_metrics"

                # Verify request count (for passthrough, should be ~100%)
                if [[ "$count" -eq 0 ]]; then
                    verify_request_count "$REQUESTS" "$echo_stats" "$name" || true
                fi

                # Log results
                local success_color="${GREEN}"
                [[ "$success" != "100" ]] && success_color="${RED}"

                log_success "$name: ${rps} req/s, p50: ${p50}ms, p99: ${p99}ms, success: ${success_color}${success}%${NC}, echo: ${echo_requests} reqs"

                # Write to CSV
                echo "$binary,$name,$count,$payload_size,$rps,$p50,$p99,$success,$cpu_percent,$peak_mem,$echo_requests,$echo_bytes" >> "$results_file"
            done
        fi
    done

    echo ""
    log_info "Generating report..."

    # Generate simple markdown report
    local report_file="$OUTPUT_DIR/report.md"
    cat > "$report_file" <<EOF
# Policy Scaling Benchmark Report - $run_what

**Date:** $(date -u +"%Y-%m-%dT%H:%M:%SZ")
**Requests per test:** $REQUESTS
**Concurrent connections:** $CONNECTIONS
**Policy counts tested:** ${POLICY_COUNTS[*]}

## Results

| Binary | Telemetry | Policies | Payload | Req/s | p50 (ms) | p99 (ms) | Success % | CPU % | Mem MB | Echo Reqs |
|--------|-----------|----------|---------|-------|----------|----------|-----------|-------|--------|-----------|
EOF

    tail -n +2 "$results_file" | while IFS=',' read -r binary name count size rps p50 p99 success cpu mem echo_req echo_bytes; do
        printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n" \
            "$binary" "$name" "$count" "$size" "$rps" "$p50" "$p99" "$success" "$cpu" "$mem" "$echo_req" >> "$report_file"
    done

    echo "" >> "$report_file"
    echo "## Verification" >> "$report_file"
    echo "" >> "$report_file"
    echo "Echo server request counts should be close to $REQUESTS for passthrough (0 policies)." >> "$report_file"
    echo "With policies, counts may be lower due to drops/sampling." >> "$report_file"

    log_success "Results saved to $results_file"
    log_success "Report saved to $report_file"
    echo ""
    cat "$report_file"
}

main "$@"
