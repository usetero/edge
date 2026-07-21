"""Stub Tero control plane for local testing.

Accepts the policy-sync POST, prints each request body to stdout (so
`docker compose logs control-plane` shows exactly what the extension reported —
including `policyStatuses`), and returns a minimal valid SyncResponse so the
provider stays healthy. Not a real control plane; just a request recorder.
"""
import http.server
import json

# Minimal proto-JSON SyncResponse the provider can decode (no policies of its
# own; the static provider supplies the policy we collect stats for).
SYNC_RESPONSE = json.dumps({
    "policies": [],
    "hash": "stub-hash",
    "syncTimestampUnixNano": "1",
    "recommendedSyncIntervalSeconds": 60,
    "syncType": 1,
    "errorMessage": "",
}).encode()

_seq = 0


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        global _seq
        _seq += 1
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode("utf-8", "replace")
        # One clear, greppable line per sync so we can see the stats reported.
        print(f"SYNC #{_seq} {self.path} :: {body}", flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(SYNC_RESPONSE)))
        self.end_headers()
        self.wfile.write(SYNC_RESPONSE)

    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_):
        pass  # silence the default access log; we print our own


http.server.HTTPServer(("0.0.0.0", 8888), Handler).serve_forever()
