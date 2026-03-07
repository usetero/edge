from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from tqdm import tqdm

from .helpers import start_tail, wait_for

RUN_ID = time.strftime("%Y-%m-%dT%H-%M-%S")
LineBuilder = Callable[[int, int], str]
LineDecoder = Callable[[str], tuple[int, int]]


def _write_policy_file(path: Path, payload: str) -> None:
    path.write_text(payload + "\n")


def _build_raw_line(line_id: int, sent_ns: int) -> str:
    return f"{line_id}:{sent_ns}\n"


def _decode_raw_line(raw: str) -> tuple[int, int]:
    left, right = raw.split(":", 1)
    return int(left), int(right)


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


def _decode_json_line(raw: str) -> tuple[int, int]:
    obj = json.loads(raw)
    return int(obj["id"]), int(obj["sent_ns"])


def _build_logfmt_line(line_id: int, sent_ns: int) -> str:
    route = "drop" if (line_id % 2) == 0 else "keep"
    return f"id={line_id} sent_ns={sent_ns} route={route} msg=msg-{line_id}\n"


def _decode_logfmt_line(raw: str) -> tuple[int, int]:
    fields: dict[str, str] = {}
    for part in raw.split():
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        fields[key] = value
    return int(fields["id"]), int(fields["sent_ns"])


def _count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    total = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            total += chunk.count(b"\n")
    return total


@dataclass
class RssSample:
    ts: float
    rss_kib: int


class RssSampler:
    def __init__(self, pid: int, interval_s: float = 0.2):
        self.pid = pid
        self.interval_s = interval_s
        self.samples: list[RssSample] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2.0)

    def _run(self) -> None:
        while not self._stop.is_set():
            rss_kib = _read_rss_kib(self.pid)
            if rss_kib is not None:
                self.samples.append(RssSample(ts=time.monotonic(), rss_kib=rss_kib))
            self._stop.wait(self.interval_s)


def _read_rss_kib(pid: int) -> int | None:
    cp = subprocess.run(
        ["ps", "-o", "rss=", "-p", str(pid)],
        check=False,
        capture_output=True,
        text=True,
    )
    if cp.returncode != 0:
        return None
    text = cp.stdout.strip()
    if not text:
        return None
    try:
        return int(text.split()[0])
    except (ValueError, IndexError):
        return None


def _read_cpu_time_s(pid: int) -> float | None:
    if os.path.exists(f"/proc/{pid}/stat"):
        return _read_cpu_time_linux(pid)
    return _read_cpu_time_ps(pid)


def _read_cpu_time_linux(pid: int) -> float | None:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().split()
        utime_ticks = int(fields[13])
        stime_ticks = int(fields[14])
        hz = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
        return (utime_ticks + stime_ticks) / float(hz)
    except (OSError, ValueError, KeyError, IndexError):
        return None


def _read_cpu_time_ps(pid: int) -> float | None:
    cp = subprocess.run(
        ["ps", "-o", "cputime=", "-p", str(pid)],
        check=False,
        capture_output=True,
        text=True,
    )
    if cp.returncode != 0:
        return None
    text = cp.stdout.strip()
    if not text:
        return None
    try:
        return _parse_cputime_to_seconds(text)
    except ValueError:
        return None


def _parse_cputime_to_seconds(value: str) -> float:
    # ps cputime formats: MM:SS, HH:MM:SS, DD-HH:MM:SS
    day = 0
    rest = value
    if "-" in value:
        day_txt, rest = value.split("-", 1)
        day = int(day_txt)
    parts = [int(p) for p in rest.split(":")]
    if len(parts) == 2:
        minute, sec = parts
        hour = 0
    elif len(parts) == 3:
        hour, minute, sec = parts
    else:
        raise ValueError(value)
    return float((((day * 24) + hour) * 60 + minute) * 60 + sec)


def _percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = int(p * (len(sorted_vals) - 1))
    return sorted_vals[idx]


def _distribution(values: list[float]) -> dict[str, float]:
    if not values:
        return {"avg": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0, "min": 0.0, "max": 0.0}
    sorted_vals = sorted(values)
    return {
        "avg": sum(sorted_vals) / len(sorted_vals),
        "p50": _percentile(sorted_vals, 0.50),
        "p95": _percentile(sorted_vals, 0.95),
        "p99": _percentile(sorted_vals, 0.99),
        "min": sorted_vals[0],
        "max": sorted_vals[-1],
    }


def _write_metrics_report(
    project_root: Path,
    profile: str,
    values: dict[str, float | int | str | dict[str, float]],
) -> None:
    out_dir = project_root / "bench" / "logging" / "results" / RUN_ID
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "logging_metrics.json"
    report: dict[str, object]
    if out_path.exists():
        report = json.loads(out_path.read_text())
    else:
        report = {
            "run_id": RUN_ID,
            "generated_at_epoch_s": time.time(),
            "profiles": {},
        }
    profiles = report.setdefault("profiles", {})
    assert isinstance(profiles, dict)
    profiles[profile] = values
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


class OutputTracker:
    def __init__(self, out_path: Path, line_decoder: LineDecoder):
        self.out_path = out_path
        self.offset = 0
        self.partial = b""
        self.seen_ids: set[int] = set()
        self.latencies_ms: list[float] = []
        self.duplicate_count = 0
        self.bad_line_count = 0
        self._line_decoder = line_decoder

    def poll(self) -> None:
        if not self.out_path.exists():
            return
        with self.out_path.open("rb") as f:
            f.seek(self.offset)
            data = f.read()
            self.offset += len(data)
        if not data:
            return
        buf = self.partial + data
        lines = buf.split(b"\n")
        self.partial = lines.pop() if lines else b""
        recv_ns = time.monotonic_ns()
        for raw in lines:
            if not raw:
                continue
            try:
                line_id, sent_ns = self._line_decoder(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                self.bad_line_count += 1
                continue
            if line_id in self.seen_ids:
                self.duplicate_count += 1
                continue
            self.seen_ids.add(line_id)
            self.latencies_ms.append((recv_ns - sent_ns) / 1_000_000.0)


def _run_sustained_profile(
    *,
    edge_tail_bin: Path,
    tmp_path: Path,
    project_root: Path,
    profile_name: str,
    file_count: int,
    duration_s: float,
    target_lps: int,
    extra_tail_args: list[str] | None = None,
    expected_output_ratio: float = 1.0,
    output_count_tolerance: int = 0,
    line_builder: LineBuilder | None = None,
    line_decoder: LineDecoder | None = None,
) -> dict[str, float | int | str | dict[str, float]]:
    out_path = tmp_path / f"{profile_name}.out"
    files = [tmp_path / f"{profile_name}-{i}.log" for i in range(file_count)]
    for f in files:
        f.write_text("")

    tail_args = [
        "-o",
        str(out_path),
        "--read-from",
        "head",
        "--poll-ms",
        "10",
        "--flush-interval-ms",
        "25",
        "--flush-lines",
        "512",
    ]
    if extra_tail_args:
        tail_args.extend(extra_tail_args)
    tail_args.extend([str(f) for f in files])

    proc = start_tail(edge_tail_bin, tmp_path / f"{profile_name}.err", tail_args)

    rss_sampler = RssSampler(proc.proc.pid)
    tracker = OutputTracker(out_path, line_decoder or _decode_raw_line)
    rss_sampler.start()
    emit_line = line_builder or _build_raw_line

    cpu_start = _read_cpu_time_s(proc.proc.pid)
    wall_start = time.monotonic()
    end_at = wall_start + duration_s

    sent_total = 0
    next_line_id = 0
    tick_s = 0.2
    lines_per_tick = max(1, int(target_lps * tick_s))
    throughput_windows: list[float] = []
    last_seen = 0
    last_window_t = wall_start

    handles = [p.open("a") for p in files]
    try:
        time.sleep(0.2)
        with tqdm(
            total=duration_s,
            desc=f"{profile_name}",
            unit="s",
            leave=True,
            dynamic_ncols=True,
        ) as bar:
            prev_t = time.monotonic()
            while time.monotonic() < end_at:
                for _ in range(lines_per_tick):
                    file_idx = next_line_id % len(handles)
                    now_ns = time.monotonic_ns()
                    handles[file_idx].write(emit_line(next_line_id, now_ns))
                    next_line_id += 1
                    sent_total += 1
                for h in handles:
                    h.flush()
                tracker.poll()

                now = time.monotonic()
                elapsed = now - last_window_t
                if elapsed >= 1.0:
                    seen_now = len(tracker.seen_ids)
                    throughput_windows.append((seen_now - last_seen) / elapsed)
                    last_seen = seen_now
                    last_window_t = now

                dt = max(0.0, now - prev_t)
                prev_t = now
                bar.update(min(dt, max(0.0, duration_s - bar.n)))
                bar.set_postfix(
                    in_lines=sent_total,
                    out_lines=len(tracker.seen_ids),
                )
                time.sleep(tick_s)

        for h in handles:
            h.flush()

        expected_out_total = int(round(sent_total * expected_output_ratio))

        def drained() -> bool:
            tracker.poll()
            return len(tracker.seen_ids) >= expected_out_total

        drain_timeout_s = max(30.0, expected_out_total / 2000.0)
        wait_for(drained, timeout_s=drain_timeout_s, poll_s=0.1)
        tracker.poll()
        wall_elapsed_s = time.monotonic() - wall_start
        cpu_end = _read_cpu_time_s(proc.proc.pid)
    finally:
        for h in handles:
            h.close()
        rss_sampler.stop()
        proc.stop()

    if cpu_start is not None and cpu_end is not None:
        cpu_avg_pct = ((cpu_end - cpu_start) / max(wall_elapsed_s, 1e-6)) * 100.0
    else:
        cpu_avg_pct = 0.0

    rss_mib_samples = [s.rss_kib / 1024.0 for s in rss_sampler.samples]
    rss_dist = _distribution(rss_mib_samples)
    throughput_dist = _distribution(throughput_windows)
    latency_dist = _distribution(tracker.latencies_ms)

    summary: dict[str, float | int | str | dict[str, float]] = {
        "mode": "sustained",
        "profile": profile_name,
        "files": file_count,
        "duration_s": duration_s,
        "target_logs_per_sec": target_lps,
        "lines_in_total": sent_total,
        "lines_out_total": len(tracker.seen_ids),
        "lines_out_expected": expected_out_total,
        "duplicates_out": tracker.duplicate_count,
        "bad_lines_out": tracker.bad_line_count,
        "elapsed_s": wall_elapsed_s,
        "logs_per_sec_avg": sent_total / wall_elapsed_s,
        "cpu_avg_pct_proc_time": cpu_avg_pct,
        "throughput_lps_dist": throughput_dist,
        "latency_ms_dist": latency_dist,
        "rss_mib_dist": rss_dist,
    }
    _write_metrics_report(project_root, profile_name, summary)

    # Data integrity checks.
    assert tracker.bad_line_count == 0, f"bad output lines: {summary}"
    assert tracker.duplicate_count == 0, f"duplicate output lines: {summary}"
    assert abs(len(tracker.seen_ids) - expected_out_total) <= output_count_tolerance, (
        f"unexpected output count: {summary}"
    )
    # Conservative throughput guardrail.
    assert (sent_total / wall_elapsed_s) > 2_000, f"throughput too low: {summary}"
    return summary


def test_benchmark_metrics_sustained_single_file(
    edge_tail_bin: Path, tmp_path: Path, project_root: Path
) -> None:
    _run_sustained_profile(
        edge_tail_bin=edge_tail_bin,
        tmp_path=tmp_path,
        project_root=project_root,
        profile_name="sustained_single_file",
        file_count=1,
        duration_s=12.0,
        target_lps=12_000,
    )


def test_benchmark_metrics_sustained_multi_file(
    edge_tail_bin: Path, tmp_path: Path, project_root: Path
) -> None:
    _run_sustained_profile(
        edge_tail_bin=edge_tail_bin,
        tmp_path=tmp_path,
        project_root=project_root,
        profile_name="sustained_multi_file",
        file_count=12,
        duration_s=12.0,
        target_lps=18_000,
    )


def test_benchmark_metrics_sustained_policy_drop_50pct(
    edge_tail_bin: Path, tmp_path: Path, project_root: Path
) -> None:
    policy_path = tmp_path / "drop-50pct-policy.json"
    _write_policy_file(
        policy_path,
        """
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
""".strip(),
    )

    _run_sustained_profile(
        edge_tail_bin=edge_tail_bin,
        tmp_path=tmp_path,
        project_root=project_root,
        profile_name="sustained_policy_drop_50pct",
        file_count=1,
        duration_s=12.0,
        target_lps=12_000,
        extra_tail_args=["--policy", str(policy_path), "-f", "raw"],
        expected_output_ratio=0.5,
        output_count_tolerance=1,
    )


def test_benchmark_metrics_sustained_policy_drop_50pct_json_attrs(
    edge_tail_bin: Path, tmp_path: Path, project_root: Path
) -> None:
    policy_path = tmp_path / "drop-50pct-json-policy.json"
    _write_policy_file(
        policy_path,
        """
{
  "policies": [
    {
      "id": "drop-route-json",
      "name": "drop-route-json",
      "log": {
        "match": [{ "log_attribute": "route", "regex": "^drop$" }],
        "keep": "none"
      }
    }
  ]
}
""".strip(),
    )

    _run_sustained_profile(
        edge_tail_bin=edge_tail_bin,
        tmp_path=tmp_path,
        project_root=project_root,
        profile_name="sustained_policy_drop_50pct_json",
        file_count=1,
        duration_s=12.0,
        target_lps=10_000,
        extra_tail_args=["--policy", str(policy_path), "-f", "json"],
        expected_output_ratio=0.5,
        output_count_tolerance=1,
        line_builder=_build_json_line,
        line_decoder=_decode_json_line,
    )


def test_benchmark_metrics_sustained_policy_drop_50pct_logfmt_attrs(
    edge_tail_bin: Path, tmp_path: Path, project_root: Path
) -> None:
    policy_path = tmp_path / "drop-50pct-logfmt-policy.json"
    _write_policy_file(
        policy_path,
        """
{
  "policies": [
    {
      "id": "drop-route-logfmt",
      "name": "drop-route-logfmt",
      "log": {
        "match": [{ "log_attribute": "route", "regex": "^drop$" }],
        "keep": "none"
      }
    }
  ]
}
""".strip(),
    )

    _run_sustained_profile(
        edge_tail_bin=edge_tail_bin,
        tmp_path=tmp_path,
        project_root=project_root,
        profile_name="sustained_policy_drop_50pct_logfmt",
        file_count=1,
        duration_s=12.0,
        target_lps=10_000,
        extra_tail_args=["--policy", str(policy_path), "-f", "logfmt"],
        expected_output_ratio=0.5,
        output_count_tolerance=1,
        line_builder=_build_logfmt_line,
        line_decoder=_decode_logfmt_line,
    )


def test_benchmark_metrics_stdin_cat(
    edge_tail_bin: Path, tmp_path: Path, project_root: Path
) -> None:
    in_path = tmp_path / "stdin-1m.in"
    err_path = tmp_path / "stdin-1m.err"
    total_lines = int(os.getenv("EDGE_TAIL_STDIN_LINES", "1000000"))
    chunk = 50_000
    short_name = f"{total_lines:.2e}"

    # Generate deterministic N-line input file with a progress bar.
    with (
        in_path.open("w") as f,
        tqdm(
            total=total_lines,
            desc=f"stdin_cat_{short_name}:generate",
            unit="lines",
            leave=True,
            dynamic_ncols=True,
        ) as bar,
    ):
        base = 0
        while base < total_lines:
            n = min(chunk, total_lines - base)
            payload = "".join(f"stdin-{i}\n" for i in range(base, base + n))
            f.write(payload)
            base += n
            bar.update(n)

    with err_path.open("wb") as err_f:
        cat_proc = subprocess.Popen(["cat", str(in_path)], stdout=subprocess.PIPE)
        try:
            assert cat_proc.stdout is not None
            tail_proc = subprocess.Popen(
                [str(edge_tail_bin), "-o", "-"],
                stdin=cat_proc.stdout,
                stdout=subprocess.PIPE,
                stderr=err_f,
            )
            cat_proc.stdout.close()
            assert tail_proc.stdout is not None
            wc_proc = subprocess.Popen(
                ["wc", "-l"],
                stdin=tail_proc.stdout,
                stdout=subprocess.PIPE,
                stderr=err_f,
                text=True,
            )
            tail_proc.stdout.close()

            rss_sampler = RssSampler(tail_proc.pid, interval_s=0.1)
            rss_sampler.start()
            cpu_start = _read_cpu_time_s(tail_proc.pid)
            t0 = time.monotonic()
            max_runtime_s = max(120.0, total_lines / 100_000.0)
            with tqdm(
                total=max_runtime_s,
                desc=f"stdin_cat_{short_name}:run",
                unit="s",
                leave=True,
                dynamic_ncols=True,
            ) as bar:
                while True:
                    rc = tail_proc.poll()
                    elapsed = time.monotonic() - t0
                    bar.n = min(elapsed, max_runtime_s)
                    bar.set_postfix(lines=total_lines)
                    bar.refresh()
                    if rc is not None:
                        tail_rc = rc
                        break
                    if elapsed > max_runtime_s:
                        tail_proc.kill()
                        raise AssertionError(
                            f"edge-tail stdin pipeline timed out after {max_runtime_s:.1f}s for {total_lines} lines"
                        )
                    time.sleep(0.2)
            cat_rc = cat_proc.wait(timeout=20.0)
            wc_out, _ = wc_proc.communicate(timeout=20.0)
            wc_rc = wc_proc.returncode
            elapsed_s = time.monotonic() - t0
            cpu_end = _read_cpu_time_s(tail_proc.pid)
            rss_sampler.stop()
        finally:
            if cat_proc.poll() is None:
                cat_proc.kill()

    if tail_rc != 0:
        err_txt = err_path.read_text(errors="replace")
        raise AssertionError(f"edge-tail stdin pipeline failed rc={tail_rc}\n{err_txt}")
    if cat_rc != 0:
        raise AssertionError(f"cat failed rc={cat_rc}")
    if wc_rc != 0:
        raise AssertionError(f"wc -l failed rc={wc_rc}")

    in_lines = total_lines
    try:
        out_lines = int(wc_out.strip().split()[0])
    except (ValueError, IndexError):
        raise AssertionError(f"failed to parse wc output: {wc_out!r}")
    assert out_lines == total_lines

    if cpu_start is not None and cpu_end is not None:
        cpu_avg_pct = ((cpu_end - cpu_start) / max(elapsed_s, 1e-6)) * 100.0
    else:
        cpu_avg_pct = 0.0

    rss_mib_samples = [s.rss_kib / 1024.0 for s in rss_sampler.samples]
    summary: dict[str, float | int | str | dict[str, float]] = {
        "mode": "stdin_cat",
        "profile": f"stdin_cat_{short_name}",
        "lines_in_total": in_lines,
        "lines_out_total": out_lines,
        "elapsed_s": elapsed_s,
        "logs_per_sec_avg": total_lines / elapsed_s,
        "cpu_avg_pct_proc_time": cpu_avg_pct,
        "rss_mib_dist": _distribution(rss_mib_samples),
    }
    _write_metrics_report(project_root, f"stdin_cat_{short_name}", summary)

    # Integrity and basic throughput guardrail.
    assert out_lines == in_lines, f"line mismatch: {summary}"
    assert (total_lines / elapsed_s) > 20_000, f"stdin throughput too low: {summary}"
