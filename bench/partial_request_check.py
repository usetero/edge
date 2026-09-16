#!/usr/bin/env python3
"""Does a stalled partial request get an answer, or is it dropped in silence?

A sender that delivers a head and then stalls has a request in flight. The
frontend must not close in silence: it owes a status and a log line. This
sends a `Content-Length: 100` head plus 10 bytes, then stalls.

usage: partial_request_check.py <edge-bin>
"""
import json, os, socket, subprocess, sys, tempfile, threading, time
sys.path.insert(0, "bench")
from health_hol_repro import SlowUpstream, free_port, probe_health
from http.server import ThreadingHTTPServer

edge_bin = sys.argv[1]
SlowUpstream.delay = 0.01
up = free_port()
srv = ThreadingHTTPServer(("127.0.0.1", up), SlowUpstream)
srv.daemon_threads = True
threading.Thread(target=srv.serve_forever, daemon=True).start()

port = free_port()
cfg = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
json.dump({"listen_address": "127.0.0.1", "listen_port": port,
           "upstream_url": "http://127.0.0.1:%d" % up,
           "log_level": "info", "max_body_size": 1048576}, cfg)
cfg.close()
log_path = "/tmp/edge-partial.log"
log = open(log_path, "wb")
edge = subprocess.Popen([edge_bin, cfg.name], stdout=log, stderr=log)

try:
    for _ in range(100):
        if probe_health(port, timeout=1.0) is not None:
            break
        time.sleep(0.1)

    s = socket.create_connection(("127.0.0.1", port), timeout=90)
    s.sendall(b"POST /api/v2/logs HTTP/1.1\r\nHost: x\r\n"
              b"Content-Type: application/json\r\nContent-Length: 100\r\n\r\n")
    s.sendall(b'[{"m":"x"')  # 9 of 100 bytes, then stall
    started = time.monotonic()
    s.settimeout(90)
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
        if b"\r\n\r\n" in data:
            break
    waited = time.monotonic() - started
    first = data.split(b"\r\n")[0].decode() if data else "connection closed with no response"
    print("  after %4.1f s the sender got: %s" % (waited, first))
    s.close()
    time.sleep(0.5)
    print("  log lines naming the drop:")
    for line in open(log_path):
        if "timeout" in line.lower() or "408" in line:
            print("    " + line.rstrip())
finally:
    edge.terminate()
    try: edge.wait(timeout=10)
    except subprocess.TimeoutExpired: edge.kill()
    srv.shutdown(); log.close(); os.unlink(cfg.name)
