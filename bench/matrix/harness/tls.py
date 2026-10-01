"""Local TLS intake for byte-integrity tests of the shared upstream clients."""

from contextlib import contextmanager
import socket
import ssl
import threading


def _serve(listener, context, stopped, failures):
    listener.settimeout(0.1)
    while not stopped.is_set():
        try:
            raw, _ = listener.accept()
        except TimeoutError:
            continue
        try:
            raw.settimeout(2)
            with context.wrap_socket(raw, server_side=True) as conn:
                conn.settimeout(1)
                pending = b""
                while not stopped.is_set():
                    while b"\r\n\r\n" not in pending:
                        try:
                            chunk = conn.recv(65536)
                        except TimeoutError:
                            # The pooled client remains idle while the harness
                            # switches to its separate, unpooled retry client.
                            if pending:
                                raise
                            break
                        if not chunk:
                            break
                        pending += chunk
                    if b"\r\n\r\n" not in pending:
                        break
                    head, pending = pending.split(b"\r\n\r\n", 1)
                    length = int(next(
                        line.split(b":", 1)[1] for line in head.split(b"\r\n")
                        if line.lower().startswith(b"content-length:")
                    ))
                    try:
                        while len(pending) < length:
                            chunk = conn.recv(65536)
                            if not chunk:
                                break
                            pending += chunk
                    except TimeoutError:
                        pass
                    body, pending = pending[:length], pending[length:]
                    expected = (bytes(range(256)) * ((length + 255) // 256))[:length]
                    if body != expected:
                        failures.append(f"declared={length}, received={len(body)}")
                        conn.sendall(b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        break
                    conn.sendall(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n")
        except (OSError, ValueError, StopIteration) as error:
            if not stopped.is_set():
                failures.append(str(error))


@contextmanager
def tls_intake(version, cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = version
    context.load_cert_chain(cert, key)
    failures = []
    stopped = threading.Event()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        thread = threading.Thread(target=_serve, args=(listener, context, stopped, failures))
        thread.start()
        try:
            yield f"https://localhost:{port}/api/v2/logs", failures
        finally:
            stopped.set()
            thread.join(timeout=5)
