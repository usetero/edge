import subprocess
import time
from pathlib import Path

from .helpers import read_lines, start_tail, wait_for_line_counts


def _write_policy(path: Path, body: str) -> None:
    path.write_text(body)


def test_policy_raw_stdin_drop(edge_tail_bin: Path, tmp_path: Path) -> None:
    policy_path = tmp_path / "raw-policy.json"
    out_path = tmp_path / "raw.out"
    _write_policy(
        policy_path,
        """
{
  "policies": [
    {
      "id": "drop-debug",
      "name": "drop-debug",
      "log": {
        "match": [{ "log_field": "body", "regex": "debug" }],
        "keep": "none"
      }
    }
  ]
}
""".strip(),
    )

    subprocess.run(
        [
            str(edge_tail_bin),
            "-o",
            str(out_path),
            "--policy",
            str(policy_path),
            "-f",
            "raw",
        ],
        input="ok\ndebug line\nnext\n",
        text=True,
        check=True,
    )
    assert read_lines(out_path) == ["ok", "next"]


def test_policy_json_attribute_drop(edge_tail_bin: Path, tmp_path: Path) -> None:
    policy_path = tmp_path / "json-policy.json"
    out_path = tmp_path / "json.out"
    _write_policy(
        policy_path,
        """
{
  "policies": [
    {
      "id": "drop-nginx",
      "name": "drop-nginx",
      "log": {
        "match": [{ "log_attribute": "ddsource", "regex": "^nginx$" }],
        "keep": "none"
      }
    }
  ]
}
""".strip(),
    )

    subprocess.run(
        [
            str(edge_tail_bin),
            "-o",
            str(out_path),
            "--policy",
            str(policy_path),
            "-f",
            "json",
        ],
        input='{"message":"a","ddsource":"nginx"}\n{"message":"b","ddsource":"app"}\n',
        text=True,
        check=True,
    )
    assert read_lines(out_path) == ['{"message":"b","ddsource":"app"}']


def test_policy_logfmt_severity_drop(edge_tail_bin: Path, tmp_path: Path) -> None:
    policy_path = tmp_path / "logfmt-policy.json"
    out_path = tmp_path / "logfmt.out"
    _write_policy(
        policy_path,
        """
{
  "policies": [
    {
      "id": "drop-debug-level",
      "name": "drop-debug-level",
      "log": {
        "match": [{ "log_field": "severity_text", "regex": "^DEBUG$" }],
        "keep": "none"
      }
    }
  ]
}
""".strip(),
    )

    subprocess.run(
        [
            str(edge_tail_bin),
            "-o",
            str(out_path),
            "--policy",
            str(policy_path),
            "-f",
            "logfmt",
        ],
        input="severity_text=DEBUG msg=drop\nseverity_text=INFO msg=keep\n",
        text=True,
        check=True,
    )
    assert read_lines(out_path) == ["severity_text=INFO msg=keep"]


def test_policy_file_tail_black_box(edge_tail_bin: Path, tmp_path: Path) -> None:
    policy_path = tmp_path / "tail-policy.json"
    in_path = tmp_path / "tail.log"
    out_path = tmp_path / "tail.out"
    in_path.write_text("")
    _write_policy(
        policy_path,
        """
{
  "policies": [
    {
      "id": "drop-debug",
      "name": "drop-debug",
      "log": {
        "match": [{ "log_field": "body", "regex": "debug" }],
        "keep": "none"
      }
    }
  ]
}
""".strip(),
    )

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "tail.err",
        [
            "-o",
            str(out_path),
            "--policy",
            str(policy_path),
            "--read-from",
            "head",
            "--poll-ms",
            "40",
            str(in_path),
        ],
    )
    try:
        time.sleep(0.2)
        with in_path.open("a") as f:
            f.write("ok\n")
            f.write("debug x\n")
            f.write("next\n")
        wait_for_line_counts(out_path, {"ok": 1, "next": 1})
    finally:
        proc.stop()

    assert read_lines(out_path) == ["ok", "next"]


def test_policy_transform_rules_do_not_mutate_output_yet(
    edge_tail_bin: Path, tmp_path: Path
) -> None:
    policy_path = tmp_path / "transform-policy.json"
    out_path = tmp_path / "transform.out"
    _write_policy(
        policy_path,
        """
{
  "policies": [
    {
      "id": "add-env",
      "name": "add-env",
      "log": {
        "match": [{ "log_field": "body", "regex": "order" }],
        "keep": "all",
        "transform": {
          "add": [{ "log_attribute": "env", "value": "prod", "upsert": true }]
        }
      }
    }
  ]
}
""".strip(),
    )

    subprocess.run(
        [
            str(edge_tail_bin),
            "-o",
            str(out_path),
            "--policy",
            str(policy_path),
            "-f",
            "raw",
        ],
        input="order accepted\n",
        text=True,
        check=True,
    )
    assert read_lines(out_path) == ["order accepted"]


def test_metric_only_policy_does_not_filter_logs(
    edge_tail_bin: Path, tmp_path: Path
) -> None:
    policy_path = tmp_path / "metric-policy.json"
    out_path = tmp_path / "metric.out"
    _write_policy(
        policy_path,
        """
{
  "policies": [
    {
      "id": "drop-metric",
      "name": "drop-metric",
      "metric": {
        "match": [{ "metric_field": "name", "regex": "^cpu\\." }],
        "keep": false
      }
    }
  ]
}
""".strip(),
    )

    subprocess.run(
        [
            str(edge_tail_bin),
            "-o",
            str(out_path),
            "--policy",
            str(policy_path),
            "-f",
            "raw",
        ],
        input="log line 1\nlog line 2\n",
        text=True,
        check=True,
    )
    assert read_lines(out_path) == ["log line 1", "log line 2"]
