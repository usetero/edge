#!/usr/bin/env bash
#
# Test data equivalence between Edge, otelcol, and Vector
#
# Usage: ./test-equivalence.sh [POLICY_COUNT]
#
# Arguments:
#   POLICY_COUNT  Number of policies to test with (default: 0 for passthrough)
#
# This script sends identical payloads to each system and compares the captured
# output to verify data equivalence.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PAYLOADS_DIR="$SCRIPT_DIR/payloads"
CONFIGS_DIR="$SCRIPT_DIR/configs/generated"

# Policy count (default 0)
POLICY_COUNT="${1:-0}"
OUTPUT_DIR="$SCRIPT_DIR/equivalence-test-${POLICY_COUNT}"

# Ports
ECHO_PORT=9999
EDGE_OTLP_PORT=8081
OTELCOL_OTLP_PORT=4318
VECTOR_OTLP_PORT=4320
TERO_COLLECTOR_OTLP_PORT=4323

# PIDs
ECHO_PID=""
EDGE_PID=""
OTELCOL_PID=""
VECTOR_PID=""
TERO_COLLECTOR_PID=""

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

cleanup() {
    log_info "Cleaning up..."
    [[ -n "$ECHO_PID" ]] && kill "$ECHO_PID" 2>/dev/null || true
    [[ -n "$EDGE_PID" ]] && kill "$EDGE_PID" 2>/dev/null || true
    [[ -n "$OTELCOL_PID" ]] && kill "$OTELCOL_PID" 2>/dev/null || true
    [[ -n "$VECTOR_PID" ]] && kill "$VECTOR_PID" 2>/dev/null || true
    [[ -n "$TERO_COLLECTOR_PID" ]] && kill "$TERO_COLLECTOR_PID" 2>/dev/null || true
    pkill -f "echo-server" 2>/dev/null || true
    pkill -f "edge-otlp" 2>/dev/null || true
    pkill -f "otelcol" 2>/dev/null || true
    pkill -f "tero-collector" 2>/dev/null || true
    pkill -f "vector.*--config" 2>/dev/null || true
    sleep 0.5
}

trap cleanup EXIT INT TERM

wait_for_port() {
    local port=$1
    local name=$2
    local max_attempts=${3:-60}
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

start_capture() {
    local name=$1
    curl -s "http://127.0.0.1:$ECHO_PORT/capture/start?name=$name" >/dev/null
}

stop_capture() {
    curl -s "http://127.0.0.1:$ECHO_PORT/capture/stop"
}

reset_echo() {
    curl -s -X POST "http://127.0.0.1:$ECHO_PORT/reset" >/dev/null
}

send_otlp_payload() {
    local port=$1
    local endpoint=$2
    local payload=$3
    local content_type=$4

    curl -s -X POST \
        -H "Content-Type: $content_type" \
        --data-binary "@$payload" \
        "http://127.0.0.1:$port$endpoint" >/dev/null
}

# Create edge config for this test
create_edge_config() {
    local config_file="$OUTPUT_DIR/edge-otlp-config.json"
    cat > "$config_file" <<EOF
{
  "listen_address": "127.0.0.1",
  "listen_port": $EDGE_OTLP_PORT,
  "upstream_url": "http://127.0.0.1:$ECHO_PORT",
  "workspace_id": "equivalence-test",
  "log_level": "err",
  "max_body_size": 4194304,
  "policy_providers": [
    {
      "id": "test-policies",
      "type": "file",
      "path": "$CONFIGS_DIR/policies-${POLICY_COUNT}.json"
    }
  ]
}
EOF
    echo "$config_file"
}

main() {
    echo ""
    echo "=========================================="
    echo "  Data Equivalence Test ($POLICY_COUNT policies)"
    echo "=========================================="
    echo ""

    cd "$PROJECT_ROOT"
    mkdir -p "$OUTPUT_DIR"

    # Generate configs for the specified policy count
    log_info "Generating configs for $POLICY_COUNT policies..."
    "$SCRIPT_DIR/generate-policies.sh" "$POLICY_COUNT" >/dev/null

    # Generate protobuf payloads
    log_info "Generating protobuf payloads..."
    python3 "$SCRIPT_DIR/generate-protobuf-payloads.py" >/dev/null

    # Build binaries
    log_info "Building binaries..."
    zig build echo-server otlp -Doptimize=ReleaseFast

    # Start echo server
    log_info "Starting echo server..."
    "$PROJECT_ROOT/zig-out/bin/echo-server" "$ECHO_PORT" "$OUTPUT_DIR" &
    ECHO_PID=$!
    wait_for_port "$ECHO_PORT" "Echo server"

    # Start Edge
    log_info "Starting Edge..."
    local edge_config=$(create_edge_config)
    "$PROJECT_ROOT/zig-out/bin/edge-otlp" "$edge_config" &
    EDGE_PID=$!
    wait_for_port "$EDGE_OTLP_PORT" "Edge OTLP"

    # Start otelcol
    OTELCOL_BIN=""
    if [[ -x "$PROJECT_ROOT/bench/bin/otelcol-contrib" ]]; then
        OTELCOL_BIN="$PROJECT_ROOT/bench/bin/otelcol-contrib"
    elif command -v otelcol-contrib >/dev/null 2>&1; then
        OTELCOL_BIN=$(command -v otelcol-contrib)
    fi

    if [[ -n "$OTELCOL_BIN" ]]; then
        log_info "Starting otelcol..."
        "$OTELCOL_BIN" --config "$CONFIGS_DIR/otelcol-${POLICY_COUNT}.yaml" &
        OTELCOL_PID=$!
        wait_for_port "$OTELCOL_OTLP_PORT" "otelcol" 120
    else
        log_warn "otelcol-contrib not found, skipping"
    fi

    # Start Vector
    VECTOR_BIN=""
    if [[ -x "$PROJECT_ROOT/bench/bin/vector" ]]; then
        VECTOR_BIN="$PROJECT_ROOT/bench/bin/vector"
    elif command -v vector >/dev/null 2>&1; then
        VECTOR_BIN=$(command -v vector)
    fi

    if [[ -n "$VECTOR_BIN" ]]; then
        log_info "Starting Vector..."
        mkdir -p "$SCRIPT_DIR/data"
        "$VECTOR_BIN" --config "$CONFIGS_DIR/vector-${POLICY_COUNT}.yaml" &
        VECTOR_PID=$!
        wait_for_port "$VECTOR_OTLP_PORT" "Vector" 120
    else
        log_warn "vector not found, skipping"
    fi

    # Start tero-collector
    TERO_COLLECTOR_BIN=""
    local known_path="/Users/jea/Code/tero/tero-collector-distro/collector/_build/tero-collector"
    if [[ -x "$known_path" ]]; then
        TERO_COLLECTOR_BIN="$known_path"
    elif [[ -x "$PROJECT_ROOT/bench/bin/tero-collector" ]]; then
        TERO_COLLECTOR_BIN="$PROJECT_ROOT/bench/bin/tero-collector"
    elif command -v tero-collector >/dev/null 2>&1; then
        TERO_COLLECTOR_BIN=$(command -v tero-collector)
    fi

    if [[ -n "$TERO_COLLECTOR_BIN" ]]; then
        log_info "Starting tero-collector..."
        "$TERO_COLLECTOR_BIN" --config "$CONFIGS_DIR/tero-collector-${POLICY_COUNT}.yaml" &
        TERO_COLLECTOR_PID=$!
        wait_for_port "$TERO_COLLECTOR_OTLP_PORT" "tero-collector" 120
    else
        log_warn "tero-collector not found, skipping"
    fi

    echo ""
    log_info "All systems started. Running tests..."

    # Test OTLP Logs
    log_info "Testing OTLP Logs..."

    reset_echo
    start_capture "edge-otlp-logs"
    send_otlp_payload "$EDGE_OTLP_PORT" "/v1/logs" "$PAYLOADS_DIR/otlp-logs.pb" "application/x-protobuf"
    sleep 0.5
    stop_capture

    if [[ -n "$OTELCOL_PID" ]]; then
        reset_echo
        start_capture "otelcol-otlp-logs"
        send_otlp_payload "$OTELCOL_OTLP_PORT" "/v1/logs" "$PAYLOADS_DIR/otlp-logs.pb" "application/x-protobuf"
        sleep 2  # otelcol batches
        stop_capture
    fi

    if [[ -n "$VECTOR_PID" ]]; then
        reset_echo
        start_capture "vector-otlp-logs"
        send_otlp_payload "$VECTOR_OTLP_PORT" "/v1/logs" "$PAYLOADS_DIR/otlp-logs.pb" "application/x-protobuf"
        sleep 2  # Vector batches
        stop_capture
    fi

    if [[ -n "$TERO_COLLECTOR_PID" ]]; then
        reset_echo
        start_capture "tero-collector-otlp-logs"
        send_otlp_payload "$TERO_COLLECTOR_OTLP_PORT" "/v1/logs" "$PAYLOADS_DIR/otlp-logs.pb" "application/x-protobuf"
        sleep 2  # tero-collector batches
        stop_capture
    fi

    # Test OTLP Traces
    log_info "Testing OTLP Traces..."

    reset_echo
    start_capture "edge-otlp-traces"
    send_otlp_payload "$EDGE_OTLP_PORT" "/v1/traces" "$PAYLOADS_DIR/otlp-traces.pb" "application/x-protobuf"
    sleep 0.5
    stop_capture

    if [[ -n "$OTELCOL_PID" ]]; then
        reset_echo
        start_capture "otelcol-otlp-traces"
        send_otlp_payload "$OTELCOL_OTLP_PORT" "/v1/traces" "$PAYLOADS_DIR/otlp-traces.pb" "application/x-protobuf"
        sleep 2
        stop_capture
    fi

    if [[ -n "$VECTOR_PID" ]]; then
        reset_echo
        start_capture "vector-otlp-traces"
        send_otlp_payload "$VECTOR_OTLP_PORT" "/v1/traces" "$PAYLOADS_DIR/otlp-traces.pb" "application/x-protobuf"
        sleep 2
        stop_capture
    fi

    if [[ -n "$TERO_COLLECTOR_PID" ]]; then
        reset_echo
        start_capture "tero-collector-otlp-traces"
        send_otlp_payload "$TERO_COLLECTOR_OTLP_PORT" "/v1/traces" "$PAYLOADS_DIR/otlp-traces.pb" "application/x-protobuf"
        sleep 2
        stop_capture
    fi

    # Test OTLP Metrics
    log_info "Testing OTLP Metrics..."

    reset_echo
    start_capture "edge-otlp-metrics"
    send_otlp_payload "$EDGE_OTLP_PORT" "/v1/metrics" "$PAYLOADS_DIR/otlp-metrics.pb" "application/x-protobuf"
    sleep 0.5
    stop_capture

    if [[ -n "$OTELCOL_PID" ]]; then
        reset_echo
        start_capture "otelcol-otlp-metrics"
        send_otlp_payload "$OTELCOL_OTLP_PORT" "/v1/metrics" "$PAYLOADS_DIR/otlp-metrics.pb" "application/x-protobuf"
        sleep 2
        stop_capture
    fi

    if [[ -n "$VECTOR_PID" ]]; then
        reset_echo
        start_capture "vector-otlp-metrics"
        send_otlp_payload "$VECTOR_OTLP_PORT" "/v1/metrics" "$PAYLOADS_DIR/otlp-metrics.pb" "application/x-protobuf"
        sleep 2
        stop_capture
    fi

    if [[ -n "$TERO_COLLECTOR_PID" ]]; then
        reset_echo
        start_capture "tero-collector-otlp-metrics"
        send_otlp_payload "$TERO_COLLECTOR_OTLP_PORT" "/v1/metrics" "$PAYLOADS_DIR/otlp-metrics.pb" "application/x-protobuf"
        sleep 2
        stop_capture
    fi

    echo ""
    log_info "Captures complete. Running comparison..."
    echo ""

    # Run the Python comparison script
    python3 "$SCRIPT_DIR/compare-captures.py" --dir "$OUTPUT_DIR"

    echo ""
    log_info "Captured files are in: $OUTPUT_DIR"
}

main "$@"
