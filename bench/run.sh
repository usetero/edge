#!/usr/bin/env bash
#
# Benchmark script for Tero Edge proxy
#
# Usage: ./bench/run.sh [OPTIONS]
#
# Options:
#   -n, --requests NUM    Number of requests per test (default: 10000)
#   -c, --connections NUM Number of concurrent connections (default: 50)
#   -o, --output DIR      Output directory for results (default: bench/results)
#   --skip-build          Skip building binaries
#   --debug               Save server logs to bench/debug/
#   -h, --help            Show this help message
#
# Requirements:
#   - oha: https://github.com/hatoo/oha (brew install oha)
#   - curl: for health checks
#   - jq: for JSON parsing
#
set -euo pipefail

# Default configuration
REQUESTS=10000
CONNECTIONS=50
OUTPUT_DIR="bench/results"
DEBUG_DIR="bench/debug"
SKIP_BUILD=false
DEBUG_MODE=false

# Ports
ECHO_SERVER_PORT=9999
DATADOG_PORT=8080
OTLP_PORT=8081

# PIDs for cleanup
ECHO_PID=""
DATADOG_PID=""
OTLP_PID=""
OTELCOL_PID=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

cleanup() {
    log_info "Cleaning up..."
    [[ -n "$ECHO_PID" ]] && kill "$ECHO_PID" 2>/dev/null || true
    [[ -n "$DATADOG_PID" ]] && kill "$DATADOG_PID" 2>/dev/null || true
    [[ -n "$OTLP_PID" ]] && kill "$OTLP_PID" 2>/dev/null || true
    [[ -n "$OTELCOL_PID" ]] && kill "$OTELCOL_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}

trap cleanup EXIT

usage() {
    sed -n '3,15p' "$0" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

# Find otelcol-contrib binary (check bench/bin first, then PATH)
find_otelcol() {
    if [[ -x "bench/bin/otelcol-contrib" ]]; then
        echo "bench/bin/otelcol-contrib"
    elif command -v otelcol-contrib >/dev/null 2>&1; then
        echo "otelcol-contrib"
    else
        echo ""
    fi
}

OTELCOL_BIN=""

check_dependencies() {
    local missing=()

    command -v oha >/dev/null 2>&1 || missing+=("oha")
    command -v curl >/dev/null 2>&1 || missing+=("curl")
    command -v jq >/dev/null 2>&1 || missing+=("jq")

    OTELCOL_BIN=$(find_otelcol)
    [[ -z "$OTELCOL_BIN" ]] && missing+=("otelcol-contrib")

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing[*]}"
        echo ""
        echo "Install with:"
        echo "  brew install oha jq"
        echo ""
        echo "For otelcol-contrib (includes Datadog support), download from GitHub releases to bench/bin/:"
        echo "  mkdir -p bench/bin"
        echo "  # For Apple Silicon (arm64):"
        echo "  curl --proto '=https' --tlsv1.2 -fOL https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.141.0/otelcol-contrib_0.141.0_darwin_arm64.tar.gz"
        echo "  tar -xvf otelcol-contrib_0.141.0_darwin_arm64.tar.gz"
        echo "  mv otelcol-contrib bench/bin/"
        echo ""
        echo "  # For Intel (amd64):"
        echo "  curl --proto '=https' --tlsv1.2 -fOL https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.141.0/otelcol-contrib_0.141.0_darwin_amd64.tar.gz"
        echo "  tar -xvf otelcol-contrib_0.141.0_darwin_amd64.tar.gz"
        echo "  mv otelcol-contrib bench/bin/"
        exit 1
    fi

    log_success "All dependencies found (otelcol-contrib: $OTELCOL_BIN)"
}

wait_for_server() {
    local port=$1
    local name=$2
    local max_attempts=30
    local attempt=0

    while ! curl -s "http://127.0.0.1:$port" >/dev/null 2>&1; do
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
        ./zig-out/bin/echo-server "$ECHO_SERVER_PORT" > "$DEBUG_DIR/echo-server.log" 2>&1 &
    else
        ./zig-out/bin/echo-server "$ECHO_SERVER_PORT" >/dev/null 2>&1 &
    fi
    ECHO_PID=$!
    wait_for_server "$ECHO_SERVER_PORT" "Echo server"
}

start_datadog_proxy() {
    local config=$1
    local mode=$2
    local scenario_name=$3

    # Kill existing if running
    [[ -n "$DATADOG_PID" ]] && kill "$DATADOG_PID" 2>/dev/null || true
    sleep 0.2

    log_info "Starting Datadog proxy ($mode)..."
    if [[ "$DEBUG_MODE" == "true" ]]; then
        local log_file="$DEBUG_DIR/datadog-$(echo "$scenario_name" | tr ' ' '-' | tr '[:upper:]' '[:lower:]').log"
        ./zig-out/bin/edge-datadog "$config" > "$log_file" 2>&1 &
    else
        ./zig-out/bin/edge-datadog "$config" >/dev/null 2>&1 &
    fi
    DATADOG_PID=$!
    wait_for_server "$DATADOG_PORT" "Datadog proxy"
}

start_otlp_proxy() {
    local config=$1
    local mode=$2
    local scenario_name=$3

    # Kill existing if running
    [[ -n "$OTLP_PID" ]] && kill "$OTLP_PID" 2>/dev/null || true
    sleep 0.2

    log_info "Starting OTLP proxy ($mode)..."
    if [[ "$DEBUG_MODE" == "true" ]]; then
        local log_file="$DEBUG_DIR/otlp-$(echo "$scenario_name" | tr ' ' '-' | tr '[:upper:]' '[:lower:]').log"
        ./zig-out/bin/edge-otlp "$config" > "$log_file" 2>&1 &
    else
        ./zig-out/bin/edge-otlp "$config" >/dev/null 2>&1 &
    fi
    OTLP_PID=$!
    wait_for_server "$OTLP_PORT" "OTLP proxy"
}

stop_otelcol() {
    if [[ -n "$OTELCOL_PID" ]]; then
        # Give otelcol time to flush any pending data
        sleep 0.3
        # Send SIGTERM for graceful shutdown
        kill -TERM "$OTELCOL_PID" 2>/dev/null || true
        # Wait briefly, then force kill if still running
        sleep 0.5
        kill -9 "$OTELCOL_PID" 2>/dev/null || true
        wait "$OTELCOL_PID" 2>/dev/null || true
        OTELCOL_PID=""
    fi
}

start_otelcol() {
    local config_file=$1
    local scenario_name=$2

    # Kill existing if running
    stop_otelcol

    # Also stop edge proxies since otelcol uses same ports
    [[ -n "$DATADOG_PID" ]] && kill "$DATADOG_PID" 2>/dev/null || true
    [[ -n "$OTLP_PID" ]] && kill "$OTLP_PID" 2>/dev/null || true
    DATADOG_PID=""
    OTLP_PID=""
    sleep 0.2

    log_info "Starting otel-collector ($config_file)..."
    if [[ "$DEBUG_MODE" == "true" ]]; then
        local log_file="$DEBUG_DIR/otelcol-$(echo "$scenario_name" | tr ' ' '-' | tr '[:upper:]' '[:lower:]').log"
        "$OTELCOL_BIN" --config "$config_file" > "$log_file" 2>&1 &
    else
        "$OTELCOL_BIN" --config "$config_file" >/dev/null 2>&1 &
    fi
    OTELCOL_PID=$!
    sleep 1  # otelcol takes a moment to start
    wait_for_server "$DATADOG_PORT" "otel-collector (Datadog)"
    wait_for_server "$OTLP_PORT" "otel-collector (OTLP)"
}

# Run a single benchmark and return JSON result
run_benchmark() {
    local url=$1
    local payload_file=$2
    local output_file=$3
    local log_file=$4

    if [[ -n "$log_file" ]]; then
        oha -n "$REQUESTS" \
            -c "$CONNECTIONS" \
            --no-tui \
            -m POST \
            -H "Content-Type: application/json" \
            -D "$payload_file" \
            --output-format json \
            -o "$output_file" \
            "$url" 2>"$log_file"
    else
        oha -n "$REQUESTS" \
            -c "$CONNECTIONS" \
            --no-tui \
            -m POST \
            -H "Content-Type: application/json" \
            -D "$payload_file" \
            --output-format json \
            -o "$output_file" \
            "$url" 2>/dev/null
    fi
}

# Extract metrics from oha JSON output
extract_metrics() {
    local json_file=$1

    if [[ ! -f "$json_file" ]]; then
        echo "N/A,N/A,N/A,N/A"
        return
    fi

    jq -r '[
        (.summary.requestsPerSec | floor),
        (.latencyPercentiles.p50 * 1000 | . * 100 | floor | . / 100),
        (.latencyPercentiles.p99 * 1000 | . * 100 | floor | . / 100),
        (.summary.successRate * 100 | floor)
    ] | @csv' "$json_file" | tr -d '"'
}

# Define all test scenarios
declare -a SCENARIOS=(
    # Format: "name|type|mode|config|endpoint|payload"
    # Edge proxy scenarios
    "Datadog Small|datadog|passthrough|bench/configs/datadog-passthrough.json|/api/v2/logs|bench/payloads/datadog-small.json"
    "Datadog Small|datadog|with-rules|bench/configs/datadog-with-rules.json|/api/v2/logs|bench/payloads/datadog-small.json"
    "Datadog Large|datadog|passthrough|bench/configs/datadog-passthrough.json|/api/v2/logs|bench/payloads/datadog-large.json"
    "Datadog Large|datadog|with-rules|bench/configs/datadog-with-rules.json|/api/v2/logs|bench/payloads/datadog-large.json"
    "Datadog 1MB|datadog|passthrough|bench/configs/datadog-passthrough.json|/api/v2/logs|bench/payloads/datadog-1mb.json"
    "Datadog 1MB|datadog|with-rules|bench/configs/datadog-with-rules.json|/api/v2/logs|bench/payloads/datadog-1mb.json"
    "OTLP Small|otlp|passthrough|bench/configs/otlp-passthrough.json|/v1/logs|bench/payloads/otlp-small.json"
    "OTLP Small|otlp|with-rules|bench/configs/otlp-with-rules.json|/v1/logs|bench/payloads/otlp-small.json"
    "OTLP Large|otlp|passthrough|bench/configs/otlp-passthrough.json|/v1/logs|bench/payloads/otlp-large.json"
    "OTLP Large|otlp|with-rules|bench/configs/otlp-with-rules.json|/v1/logs|bench/payloads/otlp-large.json"
    "OTLP 1MB|otlp|passthrough|bench/configs/otlp-passthrough.json|/v1/logs|bench/payloads/otlp-1mb.json"
    "OTLP 1MB|otlp|with-rules|bench/configs/otlp-with-rules.json|/v1/logs|bench/payloads/otlp-1mb.json"
    # OpenTelemetry Collector scenarios
    "Datadog Small|otelcol-datadog|passthrough|bench/configs/otel-collector.yaml|/api/v2/logs|bench/payloads/datadog-small.json"
    "Datadog Small|otelcol-datadog|with-rules|bench/configs/otel-collector-rules.yaml|/api/v2/logs|bench/payloads/datadog-small.json"
    "Datadog Large|otelcol-datadog|passthrough|bench/configs/otel-collector.yaml|/api/v2/logs|bench/payloads/datadog-large.json"
    "Datadog Large|otelcol-datadog|with-rules|bench/configs/otel-collector-rules.yaml|/api/v2/logs|bench/payloads/datadog-large.json"
    "Datadog 1MB|otelcol-datadog|passthrough|bench/configs/otel-collector.yaml|/api/v2/logs|bench/payloads/datadog-1mb.json"
    "Datadog 1MB|otelcol-datadog|with-rules|bench/configs/otel-collector-rules.yaml|/api/v2/logs|bench/payloads/datadog-1mb.json"
    "OTLP Small|otelcol-otlp|passthrough|bench/configs/otel-collector.yaml|/v1/logs|bench/payloads/otlp-small.json"
    "OTLP Small|otelcol-otlp|with-rules|bench/configs/otel-collector-rules.yaml|/v1/logs|bench/payloads/otlp-small.json"
    "OTLP Large|otelcol-otlp|passthrough|bench/configs/otel-collector.yaml|/v1/logs|bench/payloads/otlp-large.json"
    "OTLP Large|otelcol-otlp|with-rules|bench/configs/otel-collector-rules.yaml|/v1/logs|bench/payloads/otlp-large.json"
    "OTLP 1MB|otelcol-otlp|passthrough|bench/configs/otel-collector.yaml|/v1/logs|bench/payloads/otlp-1mb.json"
    "OTLP 1MB|otelcol-otlp|with-rules|bench/configs/otel-collector-rules.yaml|/v1/logs|bench/payloads/otlp-1mb.json"
)

run_all_scenarios() {
    local results_file="$OUTPUT_DIR/results.csv"
    local current_datadog_config=""
    local current_otlp_config=""
    local current_otelcol_config=""

    # CSV header
    echo "Scenario,Type,Mode,Payload Size,Requests/sec,p50 (ms),p99 (ms),Success %" > "$results_file"

    for scenario in "${SCENARIOS[@]}"; do
        IFS='|' read -r name type mode config endpoint payload <<< "$scenario"

        local payload_size
        payload_size=$(wc -c < "$payload" | tr -d ' ')

        local port

        # Handle otelcol scenarios
        if [[ "$type" == "otelcol-datadog" || "$type" == "otelcol-otlp" ]]; then
            # Restart otelcol if config changed or in debug mode
            if [[ "$config" != "$current_otelcol_config" ]] || [[ "$DEBUG_MODE" == "true" ]]; then
                start_otelcol "$config" "$name-$mode"
                current_otelcol_config="$config"
            fi
            if [[ "$type" == "otelcol-datadog" ]]; then
                port=$DATADOG_PORT
            else
                port=$OTLP_PORT
            fi
        # Handle edge proxy scenarios
        elif [[ "$type" == "datadog" ]]; then
            # Stop otelcol if it was running (switching back to edge)
            if [[ -n "$current_otelcol_config" ]]; then
                stop_otelcol
                current_otelcol_config=""
            fi
            if [[ "$DEBUG_MODE" == "true" || "$config" != "$current_datadog_config" ]]; then
                start_datadog_proxy "$config" "$mode" "$name-$mode"
                current_datadog_config="$config"
            fi
            port=$DATADOG_PORT
        elif [[ "$type" == "otlp" ]]; then
            # Stop otelcol if it was running (switching back to edge)
            if [[ -n "$current_otelcol_config" ]]; then
                stop_otelcol
                current_otelcol_config=""
            fi
            if [[ "$DEBUG_MODE" == "true" || "$config" != "$current_otlp_config" ]]; then
                start_otlp_proxy "$config" "$mode" "$name-$mode"
                current_otlp_config="$config"
            fi
            port=$OTLP_PORT
        fi

        local url="http://127.0.0.1:$port$endpoint"
        local output_json="$OUTPUT_DIR/$(echo "$type-$name-$mode" | tr ' ' '-' | tr '[:upper:]' '[:lower:]').json"
        local oha_log=""

        # In debug mode, save oha logs to debug directory
        if [[ "$DEBUG_MODE" == "true" ]]; then
            oha_log="$DEBUG_DIR/oha-$(echo "$type-$name-$mode" | tr ' ' '-' | tr '[:upper:]' '[:lower:]').log"
        fi

        log_info "Running: $name ($type, $mode)..."
        run_benchmark "$url" "$payload" "$output_json" "$oha_log"

        local metrics
        metrics=$(extract_metrics "$output_json")

        IFS=',' read -r rps p50 p99 success <<< "$metrics"
        log_success "$name ($type, $mode): ${rps} req/s, p50: ${p50}ms, p99: ${p99}ms"

        echo "$name,$type,$mode,$payload_size,$rps,$p50,$p99,$success" >> "$results_file"
    done
}

generate_report() {
    local report_file="$OUTPUT_DIR/report.md"
    local results_file="$OUTPUT_DIR/results.csv"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    log_info "Generating benchmark report..."

    cat > "$report_file" << EOF
# Tero Edge Benchmark Report

**Date:** $timestamp
**Requests per test:** $REQUESTS
**Concurrent connections:** $CONNECTIONS

## Results

| Scenario | Type | Mode | Payload | Req/s | p50 (ms) | p99 (ms) | Success |
|----------|------|------|---------|-------|----------|----------|---------|
EOF

    # Skip header line and format each row
    tail -n +2 "$results_file" | while IFS=',' read -r name type mode size rps p50 p99 success; do
        printf "| %s | %s | %s | %s bytes | %s | %s | %s | %s%% |\n" \
            "$name" "$type" "$mode" "$size" "$rps" "$p50" "$p99" "$success" >> "$report_file"
    done

    cat >> "$report_file" << 'EOF'

## Analysis

### Passthrough vs Rules Overhead
EOF

    # Calculate overhead for each scenario pair
    tail -n +2 "$results_file" | while IFS=',' read -r name type mode size rps p50 p99 success; do
        if [[ "$mode" == "passthrough" ]]; then
            local passthrough_rps=$rps
            local passthrough_p50=$p50
            # Find matching with-rules entry
            local rules_line
            rules_line=$(grep "^$name,$type,with-rules," "$results_file" || true)
            if [[ -n "$rules_line" ]]; then
                IFS=',' read -r _ _ _ _ rules_rps rules_p50 _ _ <<< "$rules_line"
                if [[ "$passthrough_rps" != "N/A" && "$rules_rps" != "N/A" && "$passthrough_rps" -gt 0 ]]; then
                    local overhead
                    overhead=$(echo "scale=1; (1 - $rules_rps / $passthrough_rps) * 100" | bc 2>/dev/null || echo "N/A")
                    local latency_add
                    latency_add=$(printf "%.2f" "$(echo "$rules_p50 - $passthrough_p50" | bc)" 2>/dev/null || echo "N/A")
                    echo "- **$name ($type):** ${overhead}% throughput overhead, +${latency_add}ms p50 latency" >> "$report_file"
                fi
            fi
        fi
    done

    log_success "Report saved to $report_file"
    echo ""
    cat "$report_file"
}

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--requests)
                REQUESTS="$2"
                shift 2
                ;;
            -c|--connections)
                CONNECTIONS="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --skip-build)
                SKIP_BUILD=true
                shift
                ;;
            --debug)
                DEBUG_MODE=true
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                ;;
        esac
    done

    echo ""
    echo "=========================================="
    echo "  Tero Edge Benchmark Suite"
    echo "=========================================="
    echo ""

    check_dependencies

    # Create output directory
    mkdir -p "$OUTPUT_DIR"

    # Create debug directory if debug mode enabled
    if [[ "$DEBUG_MODE" == "true" ]]; then
        mkdir -p "$DEBUG_DIR"
        rm -f "$DEBUG_DIR"/*.log
        log_info "Debug mode enabled, logs will be saved to $DEBUG_DIR/"
    fi

    # Build if needed
    if [[ "$SKIP_BUILD" == "false" ]]; then
        log_info "Building release binaries..."
        zig build echo-server datadog otlp -Doptimize=ReleaseFast
        log_success "Build complete"
    fi

    # Start echo server (upstream target)
    start_echo_server

    echo ""
    log_info "Running benchmarks: $REQUESTS requests, $CONNECTIONS connections"
    echo ""

    # Run all scenarios
    run_all_scenarios

    echo ""

    # Generate report
    generate_report

    log_success "Benchmark complete! Results in $OUTPUT_DIR/"
}

main "$@"
