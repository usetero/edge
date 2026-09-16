#!/usr/bin/env python3
"""Does a slow upstream delay /_health, and at what concurrency?

Two candidate mechanisms produce Dom's ECS symptom (three UNHEALTHY samples,
flat CPU, self-recovery):

  saturation      all `thread_pool_count` handler threads are busy, the worker
                  hits max_conn and pauses accept. Needs ~128 concurrent slow
                  requests before a health probe suffers.
  head-of-line    httpz batches up to 16 ready requests and hands the whole
                  batch to ONE pool thread (worker.zig flush), each pool thread
                  owns a private queue, and stealing is one hop. A probe queued
                  behind one slow request waits for it, however many threads are
                  idle. Needs ~1 concurrent slow request.

So the concurrency at which health latency first rises separates them. This
runs a slow fake upstream, the real edge binary, and probes /_health on a fresh
TCP connection (what an ECS health check does) while k requests are in flight.

Usage: python3 bench/health_hol_repro.py [--edge zig-out/bin/edge] [--delay 3.0]
"""

import argparse
import json
import os
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = json.dumps([{"message": "x" * 200, "ddsource": "repro"}]).encode()


class SlowUpstream(BaseHTTPRequestHandler):
    """Reads the whole body, waits, then answers 200. `delay` is set below."""

    delay = 3.0
    protocol_version = "HTTP/1.1"

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler's name
        length = int(self.headers.get("content-length") or 0)
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
        time.sleep(self.delay)
        self.send_response(200)
        self.send_header("content-length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):
        pass


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def probe_health(port, timeout=40.0):
    """One health check on a fresh connection. Returns seconds, or None."""
    started = time.monotonic()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"GET /_health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
    except (socket.timeout, OSError):
        return None
    if not data.startswith(b"HTTP/1.1 200"):
        return None
    return time.monotonic() - started


def post_logs(port, timeout=60.0):
    """One POST /api/v2/logs on a fresh connection. Returns seconds, or None."""
    started = time.monotonic()
    head = (
        "POST /api/v2/logs HTTP/1.1\r\nHost: x\r\n"
        "Content-Type: application/json\r\n"
        "Connection: close\r\n"
        "Content-Length: %d\r\n\r\n" % len(BODY)
    ).encode()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(head + BODY)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
    except (socket.timeout, OSError):
        return None
    return time.monotonic() - started


def metric(port, name):
    """One value from /_edge/metrics, or None."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
            s.sendall(b"GET /_edge/metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            data = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
    except OSError:
        return None
    for line in data.decode("utf-8", "replace").splitlines():
        if line.startswith(name + " ") or line.startswith(name + "{"):
            return line
    return None


def stats(samples):
    good = [s for s in samples if s is not None]
    misses = len(samples) - len(good)
    if not good:
        return "no successful probe (%d misses)" % misses
    good.sort()
    p50 = statistics.median(good)
    p90 = good[min(len(good) - 1, int(0.9 * len(good)))]
    return "p50 %6.0f ms   p90 %6.0f ms   max %6.0f ms   misses %d/%d" % (
        p50 * 1000, p90 * 1000, max(good) * 1000, misses, len(samples),
    )


def load_and_probe(port, concurrency, seconds, probe_every=0.25):
    """Hold `concurrency` POSTs in flight; probe health on fresh connections."""
    stop = threading.Event()

    def loader():
        while not stop.is_set():
            post_logs(port)

    threads = [threading.Thread(target=loader, daemon=True) for _ in range(concurrency)]
    for t in threads:
        t.start()
    time.sleep(1.0)  # let the load reach steady state

    # Read the saturation gauge while the load is on: it should track the
    # requests actually held by handler threads.
    gauge = metric(port, "edge_requests_in_flight")

    samples = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        samples.append(probe_health(port))
        time.sleep(probe_every)
    stop.set()
    for t in threads:
        t.join(timeout=30)
    return samples, gauge


def burst_with_health(port, posts):
    """Fire `posts` POSTs and one health probe together, so they land in one
    event-loop batch. Returns the health latency."""
    result = {}

    def health():
        result["health"] = probe_health(port)

    start = threading.Barrier(posts + 1)

    def post():
        start.wait()
        post_logs(port)

    def health_racer():
        start.wait()
        health()

    threads = [threading.Thread(target=post, daemon=True) for _ in range(posts)]
    threads.append(threading.Thread(target=health_racer, daemon=True))
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    return result.get("health")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--edge", default="zig-out/bin/edge")
    ap.add_argument("--delay", type=float, default=3.0, help="upstream latency, seconds")
    ap.add_argument("--seconds", type=float, default=10.0, help="probe window per step")
    ap.add_argument("--threads", type=int, default=0, help="TERO_THREAD_POOL_COUNT override")
    ap.add_argument("--mode", choices=("all", "burst", "load"), default="all")
    ap.add_argument("--repeats", type=int, default=3, help="burst repeats")
    ap.add_argument("--posts", type=int, default=15, help="POSTs per burst")
    args = ap.parse_args()

    SlowUpstream.delay = args.delay
    upstream_port = free_port()
    upstream = ThreadingHTTPServer(("127.0.0.1", upstream_port), SlowUpstream)
    upstream.daemon_threads = True
    threading.Thread(target=upstream.serve_forever, daemon=True).start()

    edge_port = free_port()
    config = {
        "listen_address": "127.0.0.1",
        "listen_port": edge_port,
        "upstream_url": "http://127.0.0.1:%d" % upstream_port,
        "log_level": "info",
        "max_body_size": 1048576,
    }
    cfg = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(config, cfg)
    cfg.close()

    env = dict(os.environ)
    if args.threads:
        env["TERO_THREAD_POOL_COUNT"] = str(args.threads)
    log = open("/tmp/edge-repro.log", "wb")
    edge = subprocess.Popen([args.edge, cfg.name], stdout=log, stderr=log, env=env)

    try:
        for _ in range(100):
            if probe_health(edge_port, timeout=1.0) is not None:
                break
            if edge.poll() is not None:
                sys.exit("edge exited early; see /tmp/edge-repro.log")
            time.sleep(0.1)
        else:
            sys.exit("edge never answered /_health; see /tmp/edge-repro.log")

        print("edge pid %d, port %d, upstream latency %.1fs" % (edge.pid, edge_port, args.delay))
        print("startup line: %s" % (open("/tmp/edge-repro.log").readline().strip(),))
        print()

        idle = [probe_health(edge_port) for _ in range(20)]
        print("idle                         %s" % stats(idle))
        print()

        if args.mode in ("all", "burst"):
            print("one batch: N slow POSTs + 1 health probe fired together")
            sizes = (1, 4, 8, args.posts) if args.mode == "all" else (args.posts,)
            for posts in sizes:
                got = [burst_with_health(edge_port, posts) for _ in range(args.repeats)]
                print("  %3d POSTs in the batch     %s" % (posts, stats(got)))
                over = sorted(int(g * 1000) for g in got if g is not None and g > 1.0)
                if over:
                    print("      probes over 1 s (ms): %s" % (over,))
            print()

        if args.mode in ("all", "load"):
            print("sustained load, health probed every 250 ms on a fresh connection")
            for k in (1, 4, 8, 16, 32, 64, 128):
                samples, gauge = load_and_probe(edge_port, k, args.seconds)
                print("  %3d in flight              %s   [%s]" % (k, stats(samples), gauge))
            print()

        for name in (
            "edge_requests_in_flight",
            "edge_upstream_timeouts_total",
            "edge_upstream_retries_total",
        ):
            print("%s" % (metric(edge_port, name) or (name + " (absent)")))
    finally:
        edge.terminate()
        try:
            edge.wait(timeout=10)
        except subprocess.TimeoutExpired:
            edge.kill()
        upstream.shutdown()
        log.close()
        os.unlink(cfg.name)


if __name__ == "__main__":
    main()
