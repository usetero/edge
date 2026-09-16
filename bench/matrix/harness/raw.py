"""Raw socket sender, for the requests `requests` cannot express.

A malformed head, a body shorter than its `Content-Length`, a client that
stalls mid-body: every one of those is a byte-level case, so these helpers own
the socket and the timing.
"""

from __future__ import annotations

import socket
import time


class RawResponse:
    """What came back, and how long it took."""

    def __init__(self, raw: bytes, seconds: float, closed: bool):
        self.raw = raw
        self.seconds = seconds
        self.closed = closed

    @property
    def status(self) -> int | None:
        if not self.raw.startswith(b"HTTP/"):
            return None
        try:
            return int(self.raw.split(b" ", 2)[1])
        except (IndexError, ValueError):
            return None

    @property
    def head(self) -> str:
        return self.raw.split(b"\r\n\r\n", 1)[0].decode("utf-8", "replace")

    def __repr__(self) -> str:
        return "RawResponse(status=%s, seconds=%.1f, bytes=%d)" % (
            self.status, self.seconds, len(self.raw),
        )


class RawClient:
    """One connection, driven byte by byte."""

    def __init__(self, port: int, timeout: float = 60.0):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.started = time.monotonic()

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def drip(self, data: bytes, interval: float) -> None:
        """One byte at a time. A sender that never stops but never finishes."""
        for i in range(len(data)):
            self.sock.sendall(data[i : i + 1])
            time.sleep(interval)

    def read_response(self) -> RawResponse:
        """Reads until the head is complete, the peer closes, or we time out."""
        started = time.monotonic()
        data = b""
        closed = False
        try:
            while b"\r\n\r\n" not in data:
                chunk = self.sock.recv(65536)
                if not chunk:
                    closed = True
                    break
                data += chunk
        except (socket.timeout, OSError):
            pass
        return RawResponse(data, time.monotonic() - started, closed)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self) -> "RawClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def request_head(path: str, body_len: int | None, extra: str = "", method: str = "POST") -> bytes:
    """A well-formed head. The caller decides what body follows, if any."""
    lines = [
        "%s %s HTTP/1.1" % (method, path),
        "Host: 127.0.0.1",
        "Content-Type: application/json",
    ]
    if body_len is not None:
        lines.append("Content-Length: %d" % body_len)
    if extra:
        lines.append(extra.rstrip("\r\n"))
    return ("\r\n".join(lines) + "\r\n\r\n").encode()
