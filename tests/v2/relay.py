#!/usr/bin/env python3
"""Real-process acceptance and a reproducible full-relay benchmark; stdlib only."""
import argparse
import concurrent.futures
import contextlib
import http.client
import gzip
import tempfile
import json
import os
import resource
import signal
import ssl
import socket
import socketserver
import subprocess
import sys
import threading
import time
import unittest

BINARY = os.environ.get('EDGE_V2_BINARY', 'zig-out/bin/edge-v2')

class Origin(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            line = self.rfile.readline()
            if not line:
                return
            method, path, _ = line.decode().strip().split(' ')
            headers = {}
            while (line := self.rfile.readline()) != b'\r\n':
                if not line:
                    return
                name, value = line.split(b':', 1)
                headers[name.lower()] = value.strip()
            body = b''
            if headers.get(b'transfer-encoding') == b'chunked':
                while (size := int(self.rfile.readline().split(b';')[0], 16)):
                    body += self.rfile.read(size)
                    assert self.rfile.read(2) == b'\r\n'
                while self.rfile.readline() != b'\r\n':
                    pass
            else:
                body = self.rfile.read(int(headers.get(b'content-length', b'0')))
            if path == '/stall':
                time.sleep(2)
                return
            if path == '/trickle':
                for byte in b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc':
                    self.wfile.write(bytes([byte]))
                    time.sleep(.04)
                return
            if path == '/broken':
                self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort')
                return
            if path == '/trailers':
                self.wfile.write(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n'
                                 b'Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n'
                                 b'3\r\na\x00b\r\n0\r\nX-End: yes\r\n\r\n')
                return
            if path == '/infos':
                self.wfile.write(b'HTTP/1.1 100 Continue\r\n\r\n'
                                 b'HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n')
            if path == '/big':
                body = b'x' * (512 * 1024)
            elif method == 'GET':
                body = path.encode()
            self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() +
                             b'\r\nX-Origin: yes\r\n\r\n' + (b'' if method == 'HEAD' else body))
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

@contextlib.contextmanager
def running(extra=(), tls=None, hostname="127.0.0.1"):
    with Server(('127.0.0.1', 0), Origin) as origin:
        if tls is not None:
            origin.socket = tls.wrap_socket(origin.socket, server_side=True)
        upstream = f'{hostname}:{origin.server_address[1]}'
        if tls is not None or hostname != '127.0.0.1':
            upstream = ('https://' if tls is not None else 'http://') + upstream
        thread = threading.Thread(target=origin.serve_forever, daemon=True)
        thread.start()
        with socket.socket() as port:
            port.bind(('127.0.0.1', 0))
            address = port.getsockname()
        proc = subprocess.Popen([BINARY, '--listen', f'{address[0]}:{address[1]}', '--upstream',
                                 upstream, '--workers', '2',
                                 '--requests', '2', '--connections', '16', '--timeout-ms', '700',
                                 '--body-bytes', '65536', '--response-bytes', '1048576', *extra],
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(300):
                if proc.poll() is not None:
                    raise RuntimeError(proc.stderr.read().decode())
                try:
                    with socket.create_connection(address, timeout=.1):
                        break
                except OSError:
                    time.sleep(.01)
            else:
                raise RuntimeError('relay did not start')
            yield address, proc
        finally:
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
            try:
                _, errors = proc.communicate(timeout=4)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                raise AssertionError('shutdown exceeded four seconds')
            origin.shutdown()
            thread.join()
            if proc.returncode != 0:
                raise AssertionError(f'relay exit {proc.returncode}: {errors.decode()}')
            print(errors.decode().strip())

def request(address, method='GET', path='/echo', body=None, headers=None):
    conn = http.client.HTTPConnection(*address, timeout=3)
    try:
        conn.request(method, path, body, headers or {})
        response = conn.getresponse()
        return response.status, response.read(), response.getheaders()
    finally:
        conn.close()

def raw(address, wire):
    with socket.create_connection(address, timeout=3) as sock:
        sock.sendall(wire)
        result = b''
        while chunk := sock.recv(65536):
            result += chunk
        return result

class RelayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.context = running()
        cls.address, cls.proc = cls.context.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.context.__exit__(None, None, None)

    def test_opaque_body_and_health(self):
        body = bytes(range(256)) * 128
        self.assertEqual(request(self.address, 'POST', '/echo', body)[:2], (200, body))
        self.assertEqual(request(self.address, path='/health')[:2], (200, b'ok\n'))

    def test_pipelined_order(self):
        wire = raw(self.address, b'GET /one HTTP/1.1\r\nHost: x\r\n\r\n'
                   b'GET /two HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n')
        self.assertEqual(wire.count(b'HTTP/1.1 200'), 2)
        self.assertLess(wire.index(b'/one'), wire.index(b'/two'))

    def test_chunked_request_and_trailers(self):
        wire = raw(self.address, b'POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n'
                   b'Connection: close\r\n\r\n3\r\na\x00b\r\n0\r\nX-End: yes\r\n\r\n')
        self.assertTrue(wire.endswith(b'a\x00b'), wire)
        wire = raw(self.address, b'GET /trailers HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n')
        self.assertEqual(wire.count(b'Set-Cookie:'), 2)
        self.assertTrue(wire.endswith(b'3\r\na\x00b\r\n0\r\nX-End: yes\r\n\r\n'), wire)

    def test_continue_and_interim_order(self):
        with socket.create_connection(self.address, timeout=3) as sock:
            sock.sendall(b'POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n'
                         b'Expect: 100-continue\r\nConnection: close\r\n\r\n')
            self.assertEqual(sock.recv(4096), b'HTTP/1.1 100 Continue\r\n\r\n')
            sock.sendall(b'abc')
            result = b''
            while chunk := sock.recv(4096):
                result += chunk
            self.assertTrue(result.endswith(b'abc'), result)
        wire = raw(self.address, b'GET /infos HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n')
        self.assertNotIn(b'100 Continue', wire)
        self.assertLess(wire.index(b'103 Early Hints'), wire.index(b'200 OK'))

    def test_invalid_and_oversized(self):
        for fields, status in [(b'Content-Length: 1\r\nContent-Length: 2', b'400'),
                               (b'Content-Length: 65537', b'413'),
                               (b'Expect: magic', b'417')]:
            wire = raw(self.address, b'POST /echo HTTP/1.1\r\nHost: x\r\n' + fields + b'\r\n\r\n')
            self.assertIn(status, wire.split(b'\r\n')[0])

    def test_absolute_upstream_deadline_and_truncation(self):
        for path in ['/stall', '/trickle']:
            start = time.monotonic()
            self.assertEqual(request(self.address, path=path)[0], 504)
            self.assertLess(time.monotonic() - start, 1.5)
        self.assertEqual(request(self.address, path='/broken')[0], 502)

    def test_saturation_health_and_disconnect(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            stalled = [pool.submit(request, self.address, path='/stall') for _ in range(2)]
            time.sleep(.1)
            start = time.monotonic()
            self.assertEqual(request(self.address, path='/health')[0], 200)
            self.assertLess(time.monotonic() - start, .4)
            for pending in stalled:
                self.assertEqual(pending.result()[0], 504)
        for _ in range(10):
            sock = socket.create_connection(self.address)
            sock.sendall(b'GET /big HTTP/1.1\r\nHost: x\r\n\r\n')
            sock.close()
        self.assertEqual(request(self.address)[0], 200)

    def test_half_close_and_queued_admission(self):
        with socket.create_connection(self.address, timeout=3) as sock:
            sock.sendall(b'GET /half HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n')
            sock.shutdown(socket.SHUT_WR)
            result = b''
            while chunk := sock.recv(4096):
                result += chunk
            self.assertTrue(result.endswith(b'/half'), result)
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda n: request(self.address, 'POST', '/echo', str(n).encode()), range(24)))
        self.assertEqual([r[:2] for r in results], [(200, str(n).encode()) for n in range(24)])

    def test_stalled_downstream_releases_capacity(self):
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            sock.connect(self.address)
            sock.sendall(b'GET /big HTTP/1.1\r\nHost: x\r\n\r\n')
            time.sleep(1)
            self.assertEqual(request(self.address)[0], 200)

    def test_head_and_http10(self):
        self.assertEqual(request(self.address, 'HEAD')[:2], (200, b''))
        wire = raw(self.address, b'GET /echo HTTP/1.0\r\n\r\n')
        self.assertTrue(wire.startswith(b'HTTP/1.0 200'), wire)
        self.assertIn(b'Connection: close', wire)
        wire = raw(self.address, b'GET /infos HTTP/1.0\r\n\r\n')
        self.assertNotIn(b'103 Early Hints', wire)
        self.assertTrue(wire.startswith(b'HTTP/1.0 200'), wire)

    def test_slow_reader(self):
        with socket.create_connection(self.address, timeout=3) as sock:
            sock.sendall(b'GET /big HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n')
            time.sleep(.15)
            result = b''
            while chunk := sock.recv(8192):
                result += chunk
            self.assertEqual(len(result.split(b'\r\n\r\n', 1)[1]), 512 * 1024)

class LifecycleTests(unittest.TestCase):
    def test_shutdown_with_active_and_queued_work(self):
        sockets = []
        start = None
        try:
            with running() as (address, _):
                for _ in range(4):
                    sock = socket.create_connection(address)
                    sockets.append(sock)
                    sock.sendall(b'GET /stall HTTP/1.1\r\nHost: x\r\n\r\n')
                time.sleep(.1)
                start = time.monotonic()
            self.assertLess(time.monotonic() - start, 1.5)
        finally:
            for sock in sockets:
                sock.close()

    def test_invalid_budget_never_starts_listener(self):
        result = subprocess.run([BINARY, '--budget-bytes', '1'], capture_output=True, timeout=3)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'MemoryBudgetExceeded', result.stderr)


class SecureOriginTests(unittest.TestCase):
    def test_dns_and_authenticated_tls(self):
        with running(hostname='localhost') as (address, _):
            self.assertEqual(request(address)[:2], (200, b'/echo'))
        with tempfile.TemporaryDirectory() as directory:
            cert = os.path.join(directory, 'cert.pem')
            key = os.path.join(directory, 'key.pem')
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=localhost',
                            '-addext', 'subjectAltName=DNS:localhost'], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            with running(['--ca-file', cert], tls=context, hostname='localhost') as (address, _):
                self.assertEqual(request(address)[:2], (200, b'/echo'))
            with running(['--ca-file', cert], tls=context) as (address, _):
                self.assertEqual(request(address)[0], 502, 'hostname mismatch must never bypass TLS validation')


class PolicyTests(unittest.TestCase):
    def test_drop_compression_fail_open_and_reload(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as policy_file:
            policy = {'policies': [{'id': 'drop', 'name': 'drop', 'log': {
                'match': [{'log_field': 'body', 'regex': 'drop'}], 'keep': 'none'}}]}
            json.dump(policy, policy_file)
            policy_file.flush()
            with running(['--policy-file', policy_file.name]) as (address, _):
                headers = {'Content-Type': 'application/json'}
                original = b'[ {"message":"keep"}, {"message":"drop"} ]'
                status, body, _ = request(address, 'POST', '/api/v2/logs', original, headers)
                self.assertEqual((status, json.loads(body)), (200, [{'message': 'keep'}]))
                compressed = gzip.compress(original)
                status, body, _ = request(address, 'POST', '/api/v2/logs', compressed,
                                           {**headers, 'Content-Encoding': 'gzip'})
                self.assertEqual((status, json.loads(gzip.decompress(body))), (200, [{'message': 'keep'}]))
                for broken in (b'[{"message":"drop"},]', b'[{"message":"drop"}] garbage'):
                    self.assertEqual(request(address, 'POST', '/api/v2/logs', broken, headers)[:2],
                                     (200, broken))
                self.assertEqual(request(address, 'POST', '/api/v2/logs', compressed,
                                         {**headers, 'Content-Encoding': 'unknown'})[:2], (200, compressed))
                policy_file.seek(0)
                policy_file.truncate()
                json.dump({'policies': []}, policy_file)
                policy_file.flush()
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if request(address, 'POST', '/api/v2/logs', original, headers)[1] == original:
                        break
                    time.sleep(.05)
                else:
                    self.fail('file policy removal did not become visible')

    def test_output_capacity_preserves_whole_original(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as policy_file:
            json.dump({'policies': [{'id': 'drop', 'name': 'drop', 'log': {
                'match': [{'log_field': 'body', 'regex': 'drop'}], 'keep': 'none'}}]}, policy_file)
            policy_file.flush()
            with running(['--policy-file', policy_file.name, '--output-bytes', '8']) as (address, _):
                original = b'[{"message":"drop"},{"message":"keep"}]'
                self.assertEqual(request(address, 'POST', '/api/v2/logs', original,
                                         {'Content-Type': 'application/json'})[:2], (200, original))


def benchmark(count):
    with running(['--timeout-ms', '10000']) as (address, _):
        latencies = []
        body = b'x' * 4096
        conn = http.client.HTTPConnection(*address, timeout=5)
        start = time.monotonic()
        for _ in range(count):
            then = time.monotonic()
            conn.request('POST', '/echo', body)
            response = conn.getresponse()
            assert response.status == 200 and response.read() == body
            latencies.append((time.monotonic() - then) * 1000)
        elapsed = time.monotonic() - start
        conn.close()
        latencies.sort()
        print(json.dumps({'requests': count, 'body_bytes': len(body), 'seconds': elapsed,
                          'requests_per_second': count / elapsed,
                          'p50_ms': latencies[count // 2], 'p99_ms': latencies[int(count * .99)]}))
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    print(json.dumps({'child_maxrss_bytes': usage.ru_maxrss if sys.platform == 'darwin' else usage.ru_maxrss * 1024,
                      'child_cpu_seconds': usage.ru_utime + usage.ru_stime}))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--benchmark', type=int)
    args = parser.parse_args()
    if args.benchmark:
        benchmark(args.benchmark)
    else:
        unittest.main(argv=['relay.py'], verbosity=2)
