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
VECTOR_PID=""

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
    # Stop resource monitor if running
    if [[ -n "$MONITOR_PID" ]]; then
        log_info "  Stopping monitor (PID $MONITOR_PID)..."
        kill "$MONITOR_PID" 2>/dev/null || true
    fi
    # Stop servers
    if [[ -n "$ECHO_PID" ]]; then
        log_info "  Stopping echo server (PID $ECHO_PID)..."
        kill "$ECHO_PID" 2>/dev/null || true
    fi
    if [[ -n "$DATADOG_PID" ]]; then
        log_info "  Stopping datadog proxy (PID $DATADOG_PID)..."
        kill "$DATADOG_PID" 2>/dev/null || true
    fi
    if [[ -n "$OTLP_PID" ]]; then
        log_info "  Stopping otlp proxy (PID $OTLP_PID)..."
        kill "$OTLP_PID" 2>/dev/null || true
    fi
    if [[ -n "$OTELCOL_PID" ]]; then
        log_info "  Stopping otelcol (PID $OTELCOL_PID)..."
        kill "$OTELCOL_PID" 2>/dev/null || true
    fi
    if [[ -n "$VECTOR_PID" ]]; then
        log_info "  Stopping vector (PID $VECTOR_PID)..."
        kill "$VECTOR_PID" 2>/dev/null || true
    fi
    # Clean up any leftover temp files
    log_info "  Removing temp files..."
    rm -f /tmp/bench_mem_* 2>/dev/null || true
    log_info "  Waiting for processes to exit..."
    # wait 2>/dev/null || true
    # log_info "Cleanup complete."
}

trap cleanup TERM INT EXIT

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

# Find vector binary (check ~/.vector/bin first, then PATH)
find_vector() {
    if [[ -x "$HOME/.vector/bin/vector" ]]; then
        echo "$HOME/.vector/bin/vector"
    elif command -v vector >/dev/null 2>&1; then
        echo "vector"
    else
        echo ""
    fi
}

OTELCOL_BIN=""
VECTOR_BIN=""

check_dependencies() {
    local missing=()

    command -v oha >/dev/null 2>&1 || missing+=("oha")
    command -v curl >/dev/null 2>&1 || missing+=("curl")
    command -v jq >/dev/null 2>&1 || missing+=("jq")

    OTELCOL_BIN=$(find_otelcol)
    [[ -z "$OTELCOL_BIN" ]] && missing+=("otelcol-contrib")

    VECTOR_BIN=$(find_vector)
    [[ -z "$VECTOR_BIN" ]] && missing+=("vector")

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
        echo ""
        echo "For Vector:"
        echo "  curl --proto '=https' --tlsv1.2 -sSfL https://sh.vector.dev | bash -s -- -y"
        exit 1
    fi

    log_success "All dependencies found (otelcol: $OTELCOL_BIN, vector: $VECTOR_BIN)"
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

# =============================================================================
# Resource Monitoring
# =============================================================================
# We track ACTUAL CPU TIME CONSUMED (user + sys) and calculate percentage.
# This is more reliable than sampling instantaneous CPU which varies wildly.
#
# Approach:
# 1. Record CPU time at start of benchmark
# 2. Sample memory periodically during benchmark (for peak tracking)
# 3. Record CPU time at end of benchmark
# 4. CPU% = (cpu_time_end - cpu_time_start) / wall_time * 100
#
# This gives accurate CPU utilization for the benchmark period.
# =============================================================================

# Per-scenario tracking
MONITOR_PID=""
RESOURCE_FILE=""
CPU_START_TIME=""
BENCH_START_WALL=""
MONITORED_PID=""

# Get cumulative CPU time (user + sys) in seconds for a process
get_cpu_seconds() {
    local pid=$1
    # ps -o time= gives cumulative CPU time in format "MM:SS.ss" or "HH:MM:SS.ss"
    local time_str
    time_str=$(ps -o time= -p "$pid" 2>/dev/null | tr -d ' ')

    if [[ -z "$time_str" ]]; then
        echo "0"
        return
    fi

    # Convert to seconds using awk
    # Format is typically: MM:SS.ss or H:MM:SS.ss or HH:MM:SS.ss
    echo "$time_str" | awk -F: '{
        n = NF
        # Last field may have decimal (seconds.fraction)
        secs = $n + 0  # This handles "SS" or "SS.ss"

        if (n == 2) {
            # MM:SS.ss
            mins = $1 + 0
            printf "%.2f", mins * 60 + secs
        } else if (n == 3) {
            # HH:MM:SS.ss
            hrs = $1 + 0
            mins = $2 + 0
            printf "%.2f", hrs * 3600 + mins * 60 + secs
        } else {
            printf "%.2f", secs
        }
    }'
}

# Start monitoring - record start CPU time and begin memory sampling
start_resource_monitor() {
    local target_pid=$1
    MONITORED_PID="$target_pid"
    RESOURCE_FILE=$(mktemp /tmp/bench_mem_XXXXXX)

    # Record starting CPU time and wall clock
    CPU_START_TIME=$(get_cpu_seconds "$target_pid")
    BENCH_START_WALL=$(date +%s.%N)

    # Sample memory in background (RSS in KB)
    (
        trap '' TERM INT
        local peak_rss=0
        while kill -0 "$target_pid" 2>/dev/null; do
            local rss_kb
            rss_kb=$(ps -o rss= -p "$target_pid" 2>/dev/null | tr -d ' ')
            if [[ -n "$rss_kb" ]] && [[ "$rss_kb" =~ ^[0-9]+$ ]]; then
                echo "$rss_kb" >> "$RESOURCE_FILE"
            fi
            sleep 0.1
        done
    ) 2>/dev/null &
    MONITOR_PID=$!
    disown "$MONITOR_PID" 2>/dev/null || true
}

# Stop monitoring and return cpu_percent,peak_mem_mb
stop_resource_monitor() {
    local target_pid="$MONITORED_PID"

    # Record ending CPU time and wall clock BEFORE killing monitor
    local cpu_end_time
    local wall_end
    cpu_end_time=$(get_cpu_seconds "$target_pid")
    wall_end=$(date +%s.%N)

    # Stop the memory sampling process
    if [[ -n "$MONITOR_PID" ]]; then
        kill "$MONITOR_PID" 2>/dev/null || true
        wait "$MONITOR_PID" 2>/dev/null || true
        MONITOR_PID=""
    fi

    # Calculate CPU percentage
    local cpu_used=0
    local wall_time=1
    local cpu_percent=0

    if [[ -n "$CPU_START_TIME" ]] && [[ -n "$cpu_end_time" ]]; then
        cpu_used=$(echo "$cpu_end_time - $CPU_START_TIME" | bc 2>/dev/null || echo "0")
    fi

    if [[ -n "$BENCH_START_WALL" ]] && [[ -n "$wall_end" ]]; then
        wall_time=$(echo "$wall_end - $BENCH_START_WALL" | bc 2>/dev/null || echo "1")
    fi

    if (( $(echo "$wall_time > 0" | bc -l 2>/dev/null || echo "0") )); then
        cpu_percent=$(echo "scale=1; $cpu_used / $wall_time * 100" | bc 2>/dev/null || echo "0")
    fi

    # Calculate peak memory from samples
    local peak_mem_mb=0
    if [[ -f "$RESOURCE_FILE" ]] && [[ -s "$RESOURCE_FILE" ]]; then
        local peak_kb
        peak_kb=$(sort -n "$RESOURCE_FILE" | tail -1)
        if [[ -n "$peak_kb" ]] && [[ "$peak_kb" =~ ^[0-9]+$ ]]; then
            peak_mem_mb=$(echo "scale=1; $peak_kb / 1024" | bc 2>/dev/null || echo "0")
        fi
    fi

    # Cleanup
    rm -f "$RESOURCE_FILE" 2>/dev/null
    RESOURCE_FILE=""
    CPU_START_TIME=""
    BENCH_START_WALL=""
    MONITORED_PID=""

    echo "${cpu_percent},${peak_mem_mb}"
}

# =============================================================================
# Server Management
# =============================================================================

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
    [[ -n "$DATADOG_PID" ]] && kill "$DATADOG_PID" 2>/dev/null && sleep 0.3 || true
    DATADOG_PID=""

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
    [[ -n "$OTLP_PID" ]] && kill "$OTLP_PID" 2>/dev/null && sleep 0.3 || true
    OTLP_PID=""

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
        sleep 0.3
        kill -TERM "$OTELCOL_PID" 2>/dev/null || true
        sleep 0.5
        kill -9 "$OTELCOL_PID" 2>/dev/null || true
        wait "$OTELCOL_PID" 2>/dev/null || true
        OTELCOL_PID=""
    fi
}

start_otelcol() {
    local config_file=$1
    local scenario_name=$2

    stop_otelcol
    stop_vector

    # Also stop edge proxies since otelcol uses same ports
    [[ -n "$DATADOG_PID" ]] && kill "$DATADOG_PID" 2>/dev/null || true
    [[ -n "$OTLP_PID" ]] && kill "$OTLP_PID" 2>/dev/null || true
    DATADOG_PID=""
    OTLP_PID=""
    sleep 0.3

    log_info "Starting otel-collector ($config_file)..."

    if [[ "$DEBUG_MODE" == "true" ]]; then
        local log_file="$DEBUG_DIR/otelcol-$(echo "$scenario_name" | tr ' ' '-' | tr '[:upper:]' '[:lower:]').log"
        "$OTELCOL_BIN" --config "$config_file" > "$log_file" 2>&1 &
    else
        "$OTELCOL_BIN" --config "$config_file" >/dev/null 2>&1 &
    fi
    OTELCOL_PID=$!
    sleep 1
    wait_for_server "$DATADOG_PORT" "otel-collector (Datadog)"
    wait_for_server "$OTLP_PORT" "otel-collector (OTLP)"
}

stop_vector() {
    if [[ -n "$VECTOR_PID" ]]; then
        sleep 0.3
        kill -TERM "$VECTOR_PID" 2>/dev/null || true
        sleep 0.5
        kill -9 "$VECTOR_PID" 2>/dev/null || true
        wait "$VECTOR_PID" 2>/dev/null || true
        VECTOR_PID=""
    fi
}

start_vector() {
    local config_file=$1
    local port=$2
    local scenario_name=$3

    stop_vector
    stop_otelcol

    # Also stop edge proxies since vector uses same ports
    [[ -n "$DATADOG_PID" ]] && kill "$DATADOG_PID" 2>/dev/null || true
    [[ -n "$OTLP_PID" ]] && kill "$OTLP_PID" 2>/dev/null || true
    DATADOG_PID=""
    OTLP_PID=""
    sleep 0.3

    # Create data directories for Vector
    mkdir -p /tmp/vector /tmp/vector-rules

    log_info "Starting Vector ($config_file)..."

    if [[ "$DEBUG_MODE" == "true" ]]; then
        local log_file="$DEBUG_DIR/vector-$(echo "$scenario_name" | tr ' ' '-' | tr '[:upper:]' '[:lower:]').log"
        "$VECTOR_BIN" --config "$config_file" > "$log_file" 2>&1 &
    else
        "$VECTOR_BIN" --config "$config_file" >/dev/null 2>&1 &
    fi
    VECTOR_PID=$!
    sleep 1
    wait_for_server "$port" "Vector"
}

# =============================================================================
# Benchmark Execution
# =============================================================================

run_benchmark() {
    local url=$1
    local payload_file=$2
    local output_file=$3
    local log_file=$4

    # Show TUI progress (goes to terminal), JSON output goes to file
    if [[ -n "$log_file" ]]; then
        oha -n "$REQUESTS" \
            -c "$CONNECTIONS" \
            -m POST \
            -H "Content-Type: application/json" \
            -D "$payload_file" \
            --output-format json \
            -o "$output_file" \
            "$url" 2>"$log_file"
    else
        oha -n "$REQUESTS" \
            -c "$CONNECTIONS" \
            -m POST \
            -H "Content-Type: application/json" \
            -D "$payload_file" \
            --output-format json \
            -o "$output_file" \
            "$url"
    fi
}

# Extract metrics from oha JSON output
# FIXED: Calculate success rate from HTTP status codes, not oha's successRate
# oha's successRate only measures "got a response" vs "connection failed"
# We need to check statusCodeDistribution for actual HTTP success (2xx)
extract_metrics() {
    local json_file=$1

    if [[ ! -f "$json_file" ]]; then
        echo "N/A,N/A,N/A,N/A"
        return
    fi

    # Calculate success rate from status code distribution
    # Success = 2xx responses / total responses * 100
    jq -r '
        # Get status code distribution
        .statusCodeDistribution as $dist |

        # Calculate total requests and successful (2xx) requests
        ($dist | to_entries | map(.value) | add // 0) as $total |
        ($dist | to_entries | map(select(.key | test("^2"))) | map(.value) | add // 0) as $success |

        # Calculate success percentage
        (if $total > 0 then ($success / $total * 100 | floor) else 0 end) as $success_pct |

        # Get other metrics
        [
            (.summary.requestsPerSec | floor),
            (.latencyPercentiles.p50 * 1000 | . * 100 | floor | . / 100),
            (.latencyPercentiles.p99 * 1000 | . * 100 | floor | . / 100),
            $success_pct
        ] | @csv
    ' "$json_file" | tr -d '"'
}

# Also extract detailed status code breakdown for debugging
extract_status_codes() {
    local json_file=$1

    if [[ ! -f "$json_file" ]]; then
        echo "N/A"
        return
    fi

    jq -r '.statusCodeDistribution | to_entries | map("\(.key):\(.value)") | join(" ")' "$json_file"
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
    # Vector scenarios
    "Datadog Small|vector-datadog|passthrough|bench/configs/vector.yaml|/api/v2/logs|bench/payloads/datadog-small.json"
    "Datadog Small|vector-datadog|with-rules|bench/configs/vector-rules.yaml|/api/v2/logs|bench/payloads/datadog-small.json"
    "Datadog Large|vector-datadog|passthrough|bench/configs/vector.yaml|/api/v2/logs|bench/payloads/datadog-large.json"
    "Datadog Large|vector-datadog|with-rules|bench/configs/vector-rules.yaml|/api/v2/logs|bench/payloads/datadog-large.json"
    "Datadog 1MB|vector-datadog|passthrough|bench/configs/vector.yaml|/api/v2/logs|bench/payloads/datadog-1mb.json"
    "Datadog 1MB|vector-datadog|with-rules|bench/configs/vector-rules.yaml|/api/v2/logs|bench/payloads/datadog-1mb.json"
    "OTLP Small|vector-otlp|passthrough|bench/configs/vector.yaml|/v1/logs|bench/payloads/otlp-small.json"
    "OTLP Small|vector-otlp|with-rules|bench/configs/vector-rules.yaml|/v1/logs|bench/payloads/otlp-small.json"
    "OTLP Large|vector-otlp|passthrough|bench/configs/vector.yaml|/v1/logs|bench/payloads/otlp-large.json"
    "OTLP Large|vector-otlp|with-rules|bench/configs/vector-rules.yaml|/v1/logs|bench/payloads/otlp-large.json"
    "OTLP 1MB|vector-otlp|passthrough|bench/configs/vector.yaml|/v1/logs|bench/payloads/otlp-1mb.json"
    "OTLP 1MB|vector-otlp|with-rules|bench/configs/vector-rules.yaml|/v1/logs|bench/payloads/otlp-1mb.json"
)

run_all_scenarios() {
    local results_file="$OUTPUT_DIR/results.csv"
    local current_datadog_config=""
    local current_otlp_config=""
    local current_otelcol_config=""
    local current_vector_config=""

    # CSV header
    echo "Scenario,Type,Mode,Payload Size,Requests/sec,p50 (ms),p99 (ms),Success %,CPU %,Peak Mem MB,Status Codes" > "$results_file"

    for scenario in "${SCENARIOS[@]}"; do
        IFS='|' read -r name type mode config endpoint payload <<< "$scenario"

        local payload_size
        payload_size=$(wc -c < "$payload" | tr -d ' ')

        local port
        local server_pid=""

        # Start appropriate server for this scenario (reuse if config unchanged)
        if [[ "$type" == "otelcol-datadog" || "$type" == "otelcol-otlp" ]]; then
            if [[ "$config" != "$current_otelcol_config" ]]; then
                start_otelcol "$config" "$name-$mode"
                current_otelcol_config="$config"
                current_vector_config=""
            fi
            server_pid="$OTELCOL_PID"
            if [[ "$type" == "otelcol-datadog" ]]; then
                port=$DATADOG_PORT
            else
                port=$OTLP_PORT
            fi
        elif [[ "$type" == "vector-datadog" ]]; then
            if [[ "$config" != "$current_vector_config" ]]; then
                start_vector "$config" "$DATADOG_PORT" "$name-$mode"
                current_vector_config="$config"
                current_otelcol_config=""
            fi
            server_pid="$VECTOR_PID"
            port=$DATADOG_PORT
        elif [[ "$type" == "vector-otlp" ]]; then
            if [[ "$config" != "$current_vector_config" ]]; then
                start_vector "$config" "$OTLP_PORT" "$name-$mode"
                current_vector_config="$config"
                current_otelcol_config=""
            fi
            server_pid="$VECTOR_PID"
            port=$OTLP_PORT
        elif [[ "$type" == "datadog" ]]; then
            # Stop otelcol/vector if running
            if [[ -n "$current_otelcol_config" ]]; then
                stop_otelcol
                current_otelcol_config=""
            fi
            if [[ -n "$current_vector_config" ]]; then
                stop_vector
                current_vector_config=""
            fi
            if [[ "$config" != "$current_datadog_config" ]]; then
                start_datadog_proxy "$config" "$mode" "$name-$mode"
                current_datadog_config="$config"
            fi
            server_pid="$DATADOG_PID"
            port=$DATADOG_PORT
        elif [[ "$type" == "otlp" ]]; then
            # Stop otelcol/vector if running
            if [[ -n "$current_otelcol_config" ]]; then
                stop_otelcol
                current_otelcol_config=""
            fi
            if [[ -n "$current_vector_config" ]]; then
                stop_vector
                current_vector_config=""
            fi
            if [[ "$config" != "$current_otlp_config" ]]; then
                start_otlp_proxy "$config" "$mode" "$name-$mode"
                current_otlp_config="$config"
            fi
            server_pid="$OTLP_PID"
            port=$OTLP_PORT
        fi

        local url="http://127.0.0.1:$port$endpoint"
        local output_json="$OUTPUT_DIR/$(echo "$type-$name-$mode" | tr ' ' '-' | tr '[:upper:]' '[:lower:]').json"
        local oha_log=""

        if [[ "$DEBUG_MODE" == "true" ]]; then
            oha_log="$DEBUG_DIR/oha-$(echo "$type-$name-$mode" | tr ' ' '-' | tr '[:upper:]' '[:lower:]').log"
        fi

        # Start resource monitoring
        start_resource_monitor "$server_pid"

        log_info "Running: $name ($type, $mode)..."
        run_benchmark "$url" "$payload" "$output_json" "$oha_log"

        # Stop monitoring and get metrics
        local resource_metrics
        resource_metrics=$(stop_resource_monitor)

        local metrics
        metrics=$(extract_metrics "$output_json")

        local status_codes
        status_codes=$(extract_status_codes "$output_json")

        IFS=',' read -r rps p50 p99 success <<< "$metrics"
        IFS=',' read -r cpu_percent peak_mem <<< "$resource_metrics"

        # Color code success rate
        local success_color="${GREEN}"
        if [[ "$success" != "100" ]] && [[ "$success" != "N/A" ]]; then
            success_color="${RED}"
        fi

        log_success "$name ($type, $mode): ${rps} req/s, p50: ${p50}ms, p99: ${p99}ms, success: ${success_color}${success}%${NC}, CPU: ${cpu_percent}%, Mem: ${peak_mem}MB"

        if [[ "$success" != "100" ]] && [[ "$success" != "N/A" ]]; then
            log_warn "  Status codes: $status_codes"
        fi

        echo "$name,$type,$mode,$payload_size,$rps,$p50,$p99,$success,$cpu_percent,$peak_mem,\"$status_codes\"" >> "$results_file"
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

| Scenario | Type | Mode | Payload | Req/s | p50 (ms) | p99 (ms) | Success | CPU % | Peak Mem MB |
|----------|------|------|---------|-------|----------|----------|---------|-------|-------------|
EOF

    # Skip header line and format each row
    tail -n +2 "$results_file" | while IFS=',' read -r name type mode size rps p50 p99 success cpu_pct peak_mem status_codes; do
        # Remove quotes from status_codes if present
        status_codes=$(echo "$status_codes" | tr -d '"')

        # Add warning emoji if success < 100%
        local success_indicator=""
        if [[ "$success" != "100" ]] && [[ "$success" != "N/A" ]]; then
            success_indicator=" ⚠️"
        fi

        printf "| %s | %s | %s | %s bytes | %s | %s | %s | %s%%%s | %s | %s |\n" \
            "$name" "$type" "$mode" "$size" "$rps" "$p50" "$p99" "$success" "$success_indicator" "$cpu_pct" "$peak_mem" >> "$report_file"
    done

    cat >> "$report_file" << 'EOF'

## Analysis

### Passthrough vs Rules Overhead
EOF

    # Calculate overhead for each scenario pair
    tail -n +2 "$results_file" | while IFS=',' read -r name type mode size rps p50 p99 success cpu_pct peak_mem status_codes; do
        if [[ "$mode" == "passthrough" ]]; then
            local passthrough_rps=$rps
            local passthrough_p50=$p50
            # Find matching with-rules entry
            local rules_line
            rules_line=$(grep "^$name,$type,with-rules," "$results_file" || true)
            if [[ -n "$rules_line" ]]; then
                IFS=',' read -r _ _ _ _ rules_rps rules_p50 _ _ _ _ _ <<< "$rules_line"
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

    # Add error summary if there were any non-100% success rates
    local has_errors=false
    while IFS=',' read -r name type mode size rps p50 p99 success cpu_pct peak_mem status_codes; do
        if [[ "$success" != "100" ]] && [[ "$success" != "N/A" ]] && [[ "$success" != "Success %" ]]; then
            has_errors=true
            break
        fi
    done < "$results_file"

    if [[ "$has_errors" == "true" ]]; then
        cat >> "$report_file" << 'EOF'

### Error Summary

⚠️ Some scenarios had non-2xx responses:

EOF
        tail -n +2 "$results_file" | while IFS=',' read -r name type mode size rps p50 p99 success cpu_pct peak_mem status_codes; do
            if [[ "$success" != "100" ]] && [[ "$success" != "N/A" ]]; then
                status_codes=$(echo "$status_codes" | tr -d '"')
                echo "- **$name ($type, $mode):** ${success}% success - Status codes: $status_codes" >> "$report_file"
            fi
        done
    fi

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
