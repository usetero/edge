#!/bin/bash
# Test script for Lambda extension with RIE
#
# Usage: ./test.sh [build|run|invoke|logs|stop|clean]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

case "${1:-help}" in
    build)
        echo "Building Lambda test image..."
        docker compose build
        ;;

    run)
        echo "Starting Lambda test environment..."
        docker compose up -d
        echo ""
        echo "Waiting for extension to start..."
        sleep 5
        echo ""
        echo "Lambda RIE is running. Invoke with:"
        echo "  curl -XPOST 'http://localhost:9000/2015-03-31/functions/function/invocations' -d '{\"test\":\"event\"}'"
        echo ""
        echo "View logs with: ./test.sh logs"
        ;;

    invoke)
        echo "Invoking Lambda function..."
        curl -sS -XPOST "http://localhost:9000/2015-03-31/functions/function/invocations" \
            -H "Content-Type: application/json" \
            -d '{"source":"test","message":"Hello from test script"}' | jq . || cat
        ;;

    logs)
        docker compose logs -f
        ;;

    stop)
        echo "Stopping Lambda test environment..."
        docker compose down
        ;;

    clean)
        echo "Cleaning up..."
        docker compose down -v --rmi local
        ;;

    help|*)
        echo "Lambda Extension Test Script"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  build   - Build the Docker image (compiles extension)"
        echo "  run     - Start the Lambda RIE environment"
        echo "  invoke  - Send a test invocation"
        echo "  logs    - Follow container logs"
        echo "  stop    - Stop the environment"
        echo "  clean   - Remove images and volumes"
        ;;
esac
