"""Simple test handler for Lambda extension testing."""

import json
import urllib.request
import os


def handler(event, context):
    """Test handler that sends a log to the Tero Edge extension."""

    # Get the extension port from environment
    port = os.environ.get("TERO_LISTEN_PORT", "3000")

    # Create a test log payload (Datadog logs format)
    log_payload = json.dumps([{
        "message": "Test log from Lambda function",
        "service": "test-function",
        "hostname": "lambda",
        "ddsource": "lambda",
        "ddtags": "env:test"
    }])

    try:
        # Send to the extension's local endpoint
        req = urllib.request.Request(
            f"http://localhost:{port}/api/v2/logs",
            data=log_payload.encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "DD-API-KEY": "test-key"
            },
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=5) as response:
            status = response.status
            body = response.read().decode("utf-8")

        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "Log sent to extension",
                "extension_response": {
                    "status": status,
                    "body": body
                }
            })
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": str(e)
            })
        }
