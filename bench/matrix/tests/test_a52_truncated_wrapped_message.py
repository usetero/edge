"""A52: a log whose `message` holds JSON that stops where a value belongs.

A container runtime splits a long log line (Docker splits at 16 KiB), so an
agent forwards a `message` that starts as a JSON document and stops in the
middle of it. A policy on an attribute inside the wrapped message makes the
edge parse that text. On 1.33.1, zimdjson read past the end of its token index
on a document cut after a `:`, a `,` or a `[`, and the edge segfaulted.

A cut message is text, not JSON. The edge must keep the record and forward
it unchanged, and it must still filter the valid records in the same batch.
Two policies cover both lookups into a wrapped message: an attribute matcher
(the full flatten) and a body matcher (the targeted `data.jsonPayload` walk).

The cuts go out in order of size. Each time a message is longer than the
parser's index has room for, zimdjson allocates a new index, and a ReleaseSafe
build fills the unused part with 0xaa. A read past the end then takes 0xaaaaaaaa
as an offset, which is the read that faulted. The fixture is the minimized
message from the record that crashed in production.

Against 1.33.1 in ReleaseSafe, this case failed in 12 of 12 cells on
linux/arm64 (musl), and in about half of them on macOS arm64, where the
address layout decides whether the stray read lands on a mapped page.
"""

import json
import os

from harness import MatrixCase

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "fixtures", "truncated_wrapped_message.txt")

POLICIES = {
    "policies": [
        {
            "id": "drop-event",
            "name": "drop-event",
            "log": {
                "match": [{"log_attribute": ["data", "jsonPayload", "event_type"], "exact": "drop-me"}],
                "keep": "none",
            },
        },
        {
            "id": "drop-body",
            "name": "drop-body",
            "log": {"match": [{"log_field": "body", "regex": "^drop-body"}], "keep": "none"},
        },
    ]
}


def wrapped(depth: int, event_type: str, body: str, items: int = 0) -> str:
    """A GCP-shaped document as a `message` string, nested `depth` deep.

    The nesting and the `items` come before the body, so a cut can land in
    either.
    """
    nested: object = {"leaf": [1, "two", {"three": None}], "flag": True}
    for level in range(depth):
        nested = {"level%d" % level: nested, "items": [level, {"k": "v%d" % level}, []]}
    payload = {
        "detail": nested,
        "items": [{"id": i, "tags": ["a", "b"], "ok": i % 2 == 0} for i in range(items)],
        "event_type": event_type,
        "http": {"status": 200},
        "message": body,
    }
    return json.dumps({"data": {"jsonPayload": payload}, "resource": {"type": "cloud_run_revision"}})


def record(message: str) -> dict:
    return {"ddsource": "matrix", "service": "suite", "message": message}


def cuts(document: str) -> list[str]:
    """Prefixes that end where a value belongs, in order of size.

    Every such prefix of the first 1024 characters, then prefixes that grow
    by about a third each, so the parser's index grows again and again.
    """
    ends = [i + 1 for i, ch in enumerate(document) if ch in ":,["]
    picked = [end for end in ends if end <= 1024]
    target = 1024
    for end in ends:
        if end > target:
            picked.append(end)
            target = int(end * 1.3)
    return [document[:end] for end in picked]


class TruncatedWrappedMessage(MatrixCase):
    EDGE_POLICIES = POLICIES
    FORBID_LOGS = ["request.failed", "policy.failed.open"]

    def send_and_check(self, name: str, kept: list[dict], dropped: list[dict]) -> None:
        self.intake.capture_start(name)
        before = self.metric_delta('edge_policy_records_dropped_total{telemetry="datadog_logs"}')
        response = self.post_logs(dropped + kept, timeout=30)
        self.assertTrue(self.edge.alive(), "the edge died on a cut message:\n%s" % self.edge.logs())
        self.assert_status(response, 202, "a batch with cut messages must be accepted")
        bodies = self.intake.capture_stop()
        self.assertEqual(1, len(bodies), "the intake recorded %d bodies" % len(bodies))

        # The valid records still pass through the policies: the cut ones
        # did not stop the batch or turn it into a fail-open passthrough.
        self.assertEqual(
            len(dropped),
            self.metric_delta('edge_policy_records_dropped_total{telemetry="datadog_logs"}') - before,
            "the policies did not drop the valid records they match",
        )
        # A cut message is text: its record is kept and reaches the intake
        # with the message it had.
        forwarded = [entry["message"] for entry in json.loads(bodies[0])]
        self.assertEqual([entry["message"] for entry in kept], forwarded)

    def test_cut_messages_are_kept_as_text(self):
        document = wrapped(depth=60, event_type="drop-me", body="drop-body " + "x" * 2000, items=3000)
        cut = cuts(document)
        self.assertGreater(len(cut), 100, "too few cuts to prove anything")
        kept = [record("{\"\":"), record("{\"data\":")] + [record(text) for text in cut]
        kept.append(record(wrapped(depth=3, event_type="keep-me", body="kept body")))
        dropped = [
            # Each valid record matches one policy, so each lookup path runs.
            record(wrapped(depth=3, event_type="drop-me", body="kept body")),
            record(wrapped(depth=3, event_type="keep-me", body="drop-body here")),
        ]
        # The first batch grows the parser's index from nothing. The second
        # reuses it, so a read past the end finds old offsets, not 0xaa.
        self.send_and_check("a52-first", kept, dropped)
        self.send_and_check("a52-again", kept, dropped)

    def test_the_production_message_is_kept_as_text(self):
        with open(FIXTURE, encoding="utf-8") as handle:
            message = handle.read()
        self.send_and_check("a52-production", [record(message)], [])
