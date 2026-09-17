#!/usr/bin/env python3
"""Hold N idle connections open, then ask whether the frontend recovers.

An ECS sidecar sees half-open sockets: a client that connects and sends
nothing. httpz caps that with its request timeout (limits.REQUEST_TIMEOUT_
SECONDS). The stdio frontend has no inbound timeout at all, so this measures
whether an idle connection ever gives its slot back.

usage: idle_conn_check.py <edge-bin> [conns] [wait-seconds]
"""
import json, os, socket, subprocess, sys, tempfile, threading, time
sys.path.insert(0, "bench")
from health_hol_repro import SlowUpstream, free_port, probe_health, metric
from http.server import ThreadingHTTPServer

edge_bin = sys.argv[1]
conns = int(sys.argv[2]) if len(sys.argv) > 2 else 300
wait = float(sys.argv[3]) if len(sys.argv) > 3 else 45.0

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
log = open("/tmp/edge-idle.log", "wb")
edge = subprocess.Popen([edge_bin, cfg.name], stdout=log, stderr=log)

def report(tag):
    h = probe_health(port, timeout=5.0)
    series = [metric(port, n) for n in (
        "edge_connections_active", "edge_connections_max", "edge_connections_total")]
    shed = metric(port, "edge_connections_shed_total")
    # httpz publishes its own counters through endpoints.zig; the stdio build
    # has none of them, so this shows both sides of the parity gap.
    for n in ("edge_inbound_timeouts_total", "httpz_connections",
              "httpz_timeout_request", "httpz_timeout_keepalive"):
        v = metric(port, n)
        if v:
            series.append(v)
    print("  %-22s health %-10s %s" % (
        tag, ("%.0f ms" % (h * 1000)) if h is not None else "NO 200",
        "  ".join(x for x in series + [shed] if x) or "(no conn series)"))

held = []
try:
    for _ in range(100):
        if probe_health(port, timeout=1.0) is not None:
            break
        time.sleep(0.1)
    report("idle")

    for _ in range(conns):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            held.append(s)  # connected, never sends a byte
        except OSError:
            break
    print("  held %d idle sockets" % len(held))
    time.sleep(2)
    report("with idle sockets")

    # Does anything reclaim those slots while the sockets stay open?
    waited = 0.0
    while waited < wait:
        time.sleep(15)
        waited += 15
        report("after %2.0f s" % waited)

    for s in held:
        s.close()
    held = []
    time.sleep(3)
    report("after client close")
finally:
    for s in held:
        s.close()
    edge.terminate()
    try: edge.wait(timeout=10)
    except subprocess.TimeoutExpired: edge.kill()
    srv.shutdown(); log.close(); os.unlink(cfg.name)
