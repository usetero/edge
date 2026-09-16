import os
import signal
import subprocess
import time
from pathlib import Path

from .helpers import read_lines, wait_for_process_exit


def test_stdin_pipe(edge_tail_bin: Path, tmp_path: Path) -> None:
    out = tmp_path / "stdin.out"
    subprocess.run(
        [str(edge_tail_bin), "-o", str(out)],
        input="a\nb\n",
        text=True,
        check=True,
    )
    assert read_lines(out) == ["a", "b"]


def _stdin_input() -> bytes:
    # Larger than the default write_buf (64 KiB) so the writer drains at least
    # once mid-stream and then holds a residual, which is exactly the buffer
    # the signal must flush. Ends with a newline so no partial line is stranded
    # in the framer scratch.
    lines = []
    total = 0
    i = 0
    while total < 130_000:
        line = f"line-{i:06d}-padding-content-for-buffer-test\n"
        lines.append(line)
        total += len(line)
        i += 1
    return "".join(lines).encode()


def _drain_then_signal(edge_tail_bin: Path, tmp_path: Path, sig: int) -> None:
    data = _stdin_input()
    out = tmp_path / "stdin_signal.out"
    out_f = open(out, "wb")
    proc = subprocess.Popen(
        [str(edge_tail_bin), "-"],
        stdin=subprocess.PIPE,
        stdout=out_f,
        stderr=subprocess.DEVNULL,
    )
    try:
        # Write all input but keep the write end of the pipe open: edge-tail
        # reads it, drains the writer on overflow, then blocks on the next
        # readv waiting for more data.
        assert proc.stdin is not None
        proc.stdin.write(data)
        proc.stdin.flush()

        # Wait until the pump has read all the input (output grows then stops)
        # — at that point it is blocked on the empty pipe, with the residual in
        # the write buffer. Bounded by the input size; this is fast.
        deadline = time.monotonic() + 5.0
        last = -1
        stable_since = time.monotonic()
        while time.monotonic() < deadline:
            assert proc.poll() is None, "edge-tail exited early mid-stream"
            time.sleep(0.05)
            sz = out.stat().st_size
            if sz != last:
                last = sz
                stable_since = time.monotonic()
            elif sz > 0 and time.monotonic() - stable_since >= 0.2:
                break
        pre = out.stat().st_size
        assert pre > 0, "no data drained before signal"
        assert proc.poll() is None, "edge-tail exited before signal"

        proc.send_signal(sig)
        rc = wait_for_process_exit(proc, timeout_s=4.0)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        out_f.close()

    # Clean exit (cooperative shutdown), not hard-killed by the signal, and the
    # full input reached the output: the writer drained mid-stream and the
    # residual write buffer was flushed on the main thread after the cancel.
    assert rc == 0
    assert out.stat().st_size == len(data)
    assert out.read_bytes() == data


def test_stdin_sigint_flushes_residual(edge_tail_bin: Path, tmp_path: Path) -> None:
    _drain_then_signal(edge_tail_bin, tmp_path, signal.SIGINT)


def test_stdin_sigterm_flushes_residual(edge_tail_bin: Path, tmp_path: Path) -> None:
    _drain_then_signal(edge_tail_bin, tmp_path, signal.SIGTERM)


def test_stdin_fifo_sigint_flushes_residual(edge_tail_bin: Path, tmp_path: Path) -> None:
    # The bug report's scenario: a named pipe with the write end held open
    # (e.g. `tail -f app.log | edge-tail - > out.log`), stopped with Ctrl-C.
    data = _stdin_input()
    datafile = tmp_path / "data.in"
    datafile.write_bytes(data)

    fifo = tmp_path / "et.fifo"
    os.mkfifo(fifo)
    out = tmp_path / "fifo_signal.out"

    # Feeder writes the file into the fifo, then holds the write end open
    # (sleep 30) so stdin never reaches EOF — the exact foreground-pipeline
    # Ctrl-C case.
    feeder = subprocess.Popen(["sh", "-c", f"exec 3>{fifo}; cat {datafile} >&3; sleep 30"])
    try:
        out_f = open(fifo, "rb")
        try:
            proc = subprocess.Popen(
                [str(edge_tail_bin), "-"],
                stdin=out_f,
                stdout=open(out, "wb"),
                stderr=subprocess.DEVNULL,
            )
            deadline = time.monotonic() + 5.0
            last = -1
            stable_since = time.monotonic()
            while time.monotonic() < deadline:
                assert proc.poll() is None, "edge-tail exited early mid-stream"
                time.sleep(0.05)
                sz = out.stat().st_size
                if sz != last:
                    last = sz
                    stable_since = time.monotonic()
                elif sz > 0 and time.monotonic() - stable_since >= 0.2:
                    break
            assert proc.poll() is None
            proc.send_signal(signal.SIGINT)
            rc = wait_for_process_exit(proc, timeout_s=4.0)
        finally:
            out_f.close()
        assert rc == 0
        assert out.stat().st_size == len(data)
        assert out.read_bytes() == data
    finally:
        if feeder.poll() is None:
            feeder.kill()
            feeder.wait()
