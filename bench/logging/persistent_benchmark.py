from __future__ import annotations

import argparse
import json
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def _build_raw_line(line_id: int, sent_ns: int) -> str:
    return f"{line_id}:{sent_ns}\n"


def _build_json_line(line_id: int, sent_ns: int) -> str:
    route = "drop" if (line_id % 2) == 0 else "keep"
    return (
        json.dumps(
            {
                "id": line_id,
                "sent_ns": sent_ns,
                "route": route,
                "message": f"msg-{line_id}",
            },
            separators=(",", ":"),
        )
        + "\n"
    )


def _build_logfmt_line(line_id: int, sent_ns: int) -> str:
    route = "drop" if (line_id % 2) == 0 else "keep"
    return f"id={line_id} sent_ns={sent_ns} route={route} msg=msg-{line_id}\n"


def _write_policy_file(path: Path, fmt: str) -> None:
    if fmt == "raw":
        payload = """
{
  "policies": [
    {
      "id": "drop-even-line-ids",
      "name": "drop-even-line-ids",
      "log": {
        "match": [{ "log_field": "body", "regex": "^[0-9]*[02468]:" }],
        "keep": "none"
      }
    }
  ]
}
""".strip()
    else:
        payload = """
{
  "policies": [
    {
      "id": "drop-route",
      "name": "drop-route",
      "log": {
        "match": [{ "log_attribute": "route", "regex": "^drop$" }],
        "keep": "none"
      }
    }
  ]
}
""".strip()
    path.write_text(payload + "\n")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Persistent edge-tail benchmark loop for Instruments profiling."
    )
    p.add_argument(
        "--edge-tail-bin",
        type=Path,
        default=Path("zig-out/bin/edge-tail"),
        help="Path to edge-tail binary.",
    )
    p.add_argument(
        "--work-dir",
        type=Path,
        default=None,
        help="Directory for generated inputs/output. Default: mkdtemp.",
    )
    p.add_argument("--files", type=int, default=12, help="Number of tailed files.")
    p.add_argument(
        "--target-lps",
        type=int,
        default=18_000,
        help="Target aggregate lines/sec across all files.",
    )
    p.add_argument(
        "--tick-ms",
        type=int,
        default=200,
        help="Writer tick size in milliseconds.",
    )
    p.add_argument(
        "--format",
        choices=["raw", "json", "logfmt"],
        default="raw",
        help="Input format passed to edge-tail.",
    )
    p.add_argument(
        "--drop-50pct",
        action="store_true",
        help="Enable policy that drops ~50%% of input lines.",
    )
    p.add_argument(
        "--io-engine",
        choices=["auto", "uring", "kqueue", "poll", "inotify", "epoll"],
        default="auto",
        help="edge-tail io engine.",
    )
    p.add_argument("--poll-ms", type=int, default=10, help="Watcher poll interval.")
    p.add_argument(
        "--flush-interval-ms", type=int, default=25, help="edge-tail flush interval."
    )
    p.add_argument(
        "--flush-lines", type=int, default=512, help="edge-tail flush line threshold."
    )
    p.add_argument(
        "--duration-s",
        type=float,
        default=0.0,
        help="Optional finite run length. <= 0 means run until Ctrl+C.",
    )
    p.add_argument(
        "--build",
        action="store_true",
        help="Build edge-tail (ReleaseFast) before launch.",
    )
    return p


def _build_edge_tail(args: argparse.Namespace) -> None:
    if not args.build:
        return
    subprocess.run(
        ["zig", "build", "tail", "-Doptimize=ReleaseFast"],
        check=True,
    )


def main() -> int:
    args = _build_parser().parse_args()
    _build_edge_tail(args)

    if not args.edge_tail_bin.exists():
        print(f"missing edge-tail binary: {args.edge_tail_bin}", file=sys.stderr)
        return 1
    if args.files <= 0:
        print("--files must be > 0", file=sys.stderr)
        return 1
    if args.target_lps <= 0:
        print("--target-lps must be > 0", file=sys.stderr)
        return 1
    if args.tick_ms <= 0:
        print("--tick-ms must be > 0", file=sys.stderr)
        return 1

    work_dir = (
        args.work_dir
        if args.work_dir is not None
        else Path(tempfile.mkdtemp(prefix="edge-tail-persistent-bench-"))
    )
    work_dir.mkdir(parents=True, exist_ok=True)

    out_path = work_dir / "persistent.out"
    err_path = work_dir / "persistent.err"
    in_paths = [work_dir / f"in-{idx}.log" for idx in range(args.files)]
    for p in in_paths:
        p.write_text("")

    tail_argv = [
        str(args.edge_tail_bin),
        "-o",
        str(out_path),
        "--read-from",
        "head",
        "--io-engine",
        args.io_engine,
        "--poll-ms",
        str(args.poll_ms),
        "--flush-interval-ms",
        str(args.flush_interval_ms),
        "--flush-lines",
        str(args.flush_lines),
        "-f",
        args.format,
    ]
    if args.drop_50pct:
        policy_path = work_dir / "drop-50pct-policy.json"
        _write_policy_file(policy_path, args.format)
        tail_argv.extend(["--policy", str(policy_path)])
    tail_argv.extend(str(p) for p in in_paths)

    stop = False

    def _handle_signal(_signum: int, _frame: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    with err_path.open("w") as err_f:
        proc = subprocess.Popen(
            tail_argv,
            stdout=subprocess.DEVNULL,
            stderr=err_f,
            text=True,
        )

        print("persistent benchmark started")
        print(f"  pid: {proc.pid}")
        print(f"  work_dir: {work_dir}")
        print(f"  output: {out_path}")
        print(f"  stderr: {err_path}")
        print("attach Instruments to the PID above; Ctrl+C to stop.")
        print("")

        tick_s = args.tick_ms / 1000.0
        lines_per_tick = max(1, int(args.target_lps * tick_s))
        builders = {
            "raw": _build_raw_line,
            "json": _build_json_line,
            "logfmt": _build_logfmt_line,
        }
        build_line = builders[args.format]
        line_id = 0
        sent_total = 0
        started = time.monotonic()
        last_report = started
        end_at = started + args.duration_s if args.duration_s > 0 else None
        handles = [p.open("a") for p in in_paths]

        try:
            time.sleep(0.2)
            while not stop:
                if proc.poll() is not None:
                    print(f"edge-tail exited early with rc={proc.returncode}", file=sys.stderr)
                    return 2

                now = time.monotonic()
                if end_at is not None and now >= end_at:
                    break

                for _ in range(lines_per_tick):
                    idx = line_id % len(handles)
                    handles[idx].write(build_line(line_id, time.monotonic_ns()))
                    line_id += 1
                    sent_total += 1
                for h in handles:
                    h.flush()

                if now - last_report >= 1.0:
                    elapsed = max(1e-9, now - started)
                    print(
                        f"elapsed={elapsed:8.1f}s sent={sent_total:12d} avg_lps={sent_total / elapsed:10.1f}",
                        flush=True,
                    )
                    last_report = now

                time.sleep(tick_s)
        finally:
            for h in handles:
                h.close()
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3.0)

    print("persistent benchmark stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
