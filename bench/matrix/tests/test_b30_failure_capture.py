"""B30: the failure capture writes a dump an engineer can replay.

On a relayed 408, 400 or 413, on an error out of the upstream exchange, and
when a policy stage cannot read a batch, the edge writes the outgoing body and
its metadata to `TERO_FAILURE_CAPTURE_DIR`. What the customer's engineer needs
from a dump:

- the body is the bytes the edge sent, still compressed: equal to what the
  intake received, and not the inbound body when a policy changed the batch;
- the metadata says what happened (status or error, phase, attempts, the
  watchdog) and never holds a credential;
- a dump that cannot hold the whole body says so;
- a batch the agent will drop for good (400, 413) is kept;
- the batch a decoder rejected is kept, even though its forward succeeds;
- a success, a retry that recovered, another status, and a sender that leaves
  mid-relay write nothing;
- the directory never grows past its cap, across restarts too;
- a capture that cannot open its directory never stops the data plane.
"""

import gzip
import json
import os
import socket
import struct
import time

import requests

from harness import Edge, MatrixCase

SECRET = "matrix-secret-api-key"
QUERY_SECRET = "matrix-secret-query-key"
AGENT_HEADERS = {
    "DD-API-KEY": SECRET,
    "DD-EVP-ORIGIN": "agent",
    "Content-Encoding": "gzip",
}
# Above `large_body_buffer_size` (64 KiB), so the edge streams the body.
STREAMED_BYTES = 300 * 1024


def check_dump(case, dump, body, status=None, err=None, phase=None, complete=True):
    """The shared expectations for one dump."""
    meta = dump.meta
    case.assertNotIn(SECRET, dump.raw_meta, "the API key reached the disk")
    case.assertNotIn(QUERY_SECRET, dump.raw_meta, "the query key reached the disk")
    headers = {h["name"].lower(): h["value"] for h in meta["headers"]}
    case.assertEqual(headers.get("dd-api-key"), "[redacted]", "the key header must keep its name")
    case.assertEqual(headers.get("dd-evp-origin"), "agent", "a plain header must survive")
    case.assertEqual(meta["method"], "POST")
    case.assertTrue(meta["url"].startswith(case.intake.url), meta["url"])
    case.assertEqual(meta["outcome"]["status"], status, meta)
    case.assertEqual(meta["outcome"]["err"], err, meta)
    if phase is not None:
        case.assertEqual(meta["outcome"]["phase"], phase, meta)
    case.assertEqual(meta["body"]["framing"], "content_length")
    case.assertEqual(meta["body"]["captured_bytes"], len(dump.body))
    case.assertEqual(meta["body"]["complete"], complete, meta)
    if complete:
        case.assertEqual(meta["body"]["declared_bytes"], len(dump.body))
        case.assertEqual(dump.body, body, "the dump is not the body the edge sent")
    else:
        case.assertLess(len(dump.body), meta["body"]["declared_bytes"], meta)
        case.assertEqual(dump.body, body[: len(dump.body)], "a partial dump must be a prefix")


def post(case, body, query="", headers=None, timeout=60.0, path="/api/v2/logs"):
    merged = dict(AGENT_HEADERS)
    merged.update(headers or {})
    return case.post_raw_body(body, path=path + query, headers=merged, timeout=timeout)


class Relayed408IsCaptured(MatrixCase):
    """The production signature: the intake waited and answered 408."""

    CAPTURE_MAX_DUMPS = 10
    EXPECT_LOGS = ["upstream.failure.captured"]

    def test_a_buffered_batch(self):
        body = self.gzipped(json.loads(self.log_batch(8 * 1024)))
        self.intake.capture_start("b30-buffered")
        self.intake.arm("status", 408, count=1)
        response = post(self, body, query="?dd-api-key=%s&ddsource=matrix" % QUERY_SECRET)
        self.assert_status(response, 408, "the intake's 408 must be relayed")
        received = self.intake.capture_stop()

        dumps = self.captures.wait_for(1)
        self.assertEqual(len(dumps), 1, "a relayed 408 must write exactly one dump")
        self.assertEqual(received, [body], "the intake did not receive the batch as sent")
        check_dump(self, dumps[0], body, status=408, phase="response")
        meta = dumps[0].meta
        self.assertIn("dd-api-key=[redacted]", meta["url"])
        self.assertIn("ddsource=matrix", meta["url"], "a plain query parameter must survive")
        self.assertEqual(meta["outcome"]["attempts"], 1)
        self.assertFalse(meta["outcome"]["watchdog_fired"])

    def test_a_streamed_batch(self):
        body = gzip.compress(os.urandom(STREAMED_BYTES))
        self.assertGreater(len(body), 64 * 1024, "the batch must stream")
        self.intake.capture_start("b30-streamed")
        self.intake.arm("status", 408, count=1)
        self.assert_status(post(self, body), 408)
        received = self.intake.capture_stop()

        dumps = self.captures.wait_for(1)
        self.assertEqual(len(dumps), 1)
        self.assertEqual(received, [body])
        check_dump(self, dumps[0], body, status=408, phase="response")

    def test_a_chunked_batch(self):
        body = self.gzipped(json.loads(self.log_batch(4 * 1024)))
        self.intake.arm("status", 408, count=1)

        def chunks():
            for start in range(0, len(body), 700):
                yield body[start : start + 700]

        response = post(self, chunks())
        self.assert_status(response, 408)
        dumps = self.captures.wait_for(1)
        self.assertEqual(len(dumps), 1)
        # The dump holds what went upstream: the de-chunked body with a length.
        check_dump(self, dumps[0], body, status=408, phase="response")


class DroppedByTheAgentIsCaptured(MatrixCase):
    """400 and 413 make the agent drop the batch for good: the dump is the only copy."""

    CAPTURE_MAX_DUMPS = 10
    # The metrics carry only the status class. The early reject never reaches
    # the intake's counter, so the invariant reads the relayed 400 as ours.
    # b05 owns that relay; this case owns the dump.
    EXPECT_PERMANENT_DROP = True

    def test_relayed_400_and_413(self):
        bodies = {}
        for status in (400, 413):
            bodies[status] = self.gzipped([{"message": "drop-class %d" % status}])
            self.intake.capture_start("b30-%d" % status)
            self.intake.arm("status", status, count=1)
            self.assert_status(post(self, bodies[status]), status, "the intake's %d must be relayed" % status)
            self.assertEqual(self.intake.capture_stop(), [bodies[status]])
        dumps = self.captures.wait_for(2)
        self.assertEqual([d.meta["outcome"]["status"] for d in dumps], [400, 413])
        for dump in dumps:
            status = dump.meta["outcome"]["status"]
            check_dump(self, dump, bodies[status], status=status, phase="response")

    def test_an_early_reject(self):
        body = self.gzipped()
        self.intake.arm("reject_early", count=1)
        self.assert_status(post(self, body), 400)
        dumps = self.captures.wait_for(1)
        self.assertEqual(len(dumps), 1, "the intake rejected on the head; the batch is still ours to keep")
        check_dump(self, dumps[0], body, status=400, phase="response")


FAIL_OPEN_POLICIES = {
    "policies": [
        {
            "id": "drop-debug",
            "name": "drop-debug",
            "log": {"match": [{"log_field": "body", "regex": "^DEBUG"}], "keep": "none"},
        },
        {
            "id": "drop-load",
            "name": "drop-load",
            "metric": {"match": [{"metric_field": "name", "regex": "^system\\.load"}], "keep": False},
        },
    ]
}


def series_body() -> bytes:
    points = [
        {"metric": "%s.%d" % ("system.load" if i % 2 else "app.requests", i), "points": [{"timestamp": 1, "value": i}], "type": 3}
        for i in range(400)
    ]
    return json.dumps({"series": points}).encode()


class PolicyFailOpenIsCaptured(MatrixCase):
    """A batch the decoder cannot read is forwarded untouched, and kept."""

    CAPTURE_MAX_DUMPS = 10
    EDGE_POLICIES = FAIL_OPEN_POLICIES
    EXPECT_LOGS = ["policy.failed.open", "upstream.failure.captured"]

    def check_fail_open(self, path, stream, phases):
        cut = stream[: len(stream) // 2]
        self.intake.capture_start("b30-failopen")
        self.assert_status(post(self, cut, path=path), 202, "a cut stream must fail open")
        self.assertEqual(self.intake.capture_stop(), [cut], "the forward must be untouched")
        dumps = self.captures.wait_for(1)
        self.assertEqual(len(dumps), 1, "one unreadable batch, one dump")
        meta = dumps[0].meta
        self.assertIn(meta["outcome"]["phase"], phases, meta)
        self.assertIsNotNone(meta["outcome"]["err"], "the dump must name the decoder error")
        check_dump(self, dumps[0], cut, err=meta["outcome"]["err"])
        self.assertEqual(meta["outcome"]["attempts"], 0)

    def test_the_streamed_logs_path(self):
        stream = gzip.compress(self.log_batch(30_000, level="DEBUG"), 1)
        self.check_fail_open("/api/v2/logs", stream, ("policy_probe", "policy_encode"))

    def test_the_buffered_metrics_path(self):
        self.check_fail_open("/api/v2/series", gzip.compress(series_body(), 1), ("policy_buffered",))

    def test_a_fail_open_whose_forward_fails_is_kept_twice(self):
        stream = gzip.compress(self.log_batch(30_000, level="DEBUG"), 1)
        cut = stream[: len(stream) // 2]
        self.intake.arm("status", 408, count=1)
        self.assert_status(post(self, cut), 408)
        dumps = self.captures.wait_for(2)
        self.assertEqual(len(dumps), 2, "the unreadable batch and the failed forward are two facts")
        self.assertIn("response", [d.meta["outcome"]["phase"] for d in dumps])
        for dump in dumps:
            self.assertEqual(dump.body, cut)


class PolicyChangedBatchIsCapturedAsSent(MatrixCase):
    """A policy rewrites the batch, so the dump must hold the outgoing bytes."""

    CAPTURE_MAX_DUMPS = 10
    EDGE_POLICIES = {
        "policies": [
            {
                "id": "drop-debug",
                "name": "drop-debug",
                "log": {"match": [{"log_field": "body", "regex": "DEBUG"}], "keep": "none"},
            }
        ]
    }

    def test_the_dump_is_the_rewritten_batch(self):
        records = json.loads(self.log_batch(6 * 1024, level="INFO")) + json.loads(
            self.log_batch(6 * 1024, level="DEBUG")
        )
        inbound = self.gzipped(records)
        self.intake.capture_start("b30-policy")
        self.intake.arm("status", 408, count=1)
        self.assert_status(post(self, inbound), 408)
        received = self.intake.capture_stop()
        self.assertEqual(len(received), 1)
        self.assertNotEqual(received[0], inbound, "the policy changed nothing, so the case proves nothing")

        dumps = self.captures.wait_for(1)
        self.assertEqual(len(dumps), 1)
        check_dump(self, dumps[0], received[0], status=408, phase="response")
        self.assertNotIn(b"DEBUG", gzip.decompress(dumps[0].body))


class TransportFailureIsCaptured(MatrixCase):
    CAPTURE_MAX_DUMPS = 10
    EXPECT_LOGS = ["upstream.failure.captured", "request.failed"]

    def test_a_buffered_batch_that_fails_both_attempts(self):
        body = self.gzipped()
        self.intake.arm("reset", count=2)
        response = post(self, body)
        self.assertEqual(response.status_code // 100, 5, "got %d" % response.status_code)

        dumps = self.captures.wait_for(1)
        self.assertEqual(len(dumps), 1, "one failed request, one dump")
        check_dump(self, dumps[0], body, err="UpstreamTransportFailed", phase="send_or_head")
        outcome = dumps[0].meta["outcome"]
        self.assertEqual(outcome["attempts"], 2, "the retry must be recorded")
        self.assertIsNotNone(outcome["retried_err"], "the first attempt's error must be recorded")

    def test_a_streamed_batch_is_not_retried(self):
        body = gzip.compress(os.urandom(STREAMED_BYTES))
        self.intake.arm("reset", count=1)
        response = post(self, body)
        self.assertEqual(response.status_code // 100, 5, "got %d" % response.status_code)

        dumps = self.captures.wait_for(1)
        self.assertEqual(len(dumps), 1)
        meta = dumps[0].meta
        self.assertEqual(meta["outcome"]["attempts"], 1)
        self.assertIsNotNone(meta["outcome"]["err"])
        # The body fits in the 512 KiB pump buffer, so the edge has read all
        # of it before its first upstream write, and the dump is whole.
        check_dump(self, dumps[0], body, err=meta["outcome"]["err"])

    def test_nothing_listening(self):
        self.intake.stop()
        body = self.gzipped()
        response = post(self, body)
        self.assert_status(response, 502)
        dumps = self.captures.wait_for(1)
        self.assertEqual(len(dumps), 1)
        check_dump(self, dumps[0], body, err=dumps[0].meta["outcome"]["err"], phase="dial")
        self.assertIsNotNone(dumps[0].meta["outcome"]["err"])


class WatchdogTimeoutIsCaptured(MatrixCase):
    CAPTURE_MAX_DUMPS = 10
    SLOW = True
    EXPECT_LOGS = ["upstream.timed.out", "upstream.failure.captured"]

    def test_the_dump_names_the_watchdog(self):
        body = self.gzipped()
        self.intake.arm("hang", count=1)
        self.assert_status(post(self, body, timeout=120), 504)
        dumps = self.captures.wait_for(1)
        self.assertEqual(len(dumps), 1)
        check_dump(self, dumps[0], body, err="UpstreamTimeout", phase="send_or_head")
        self.assertTrue(dumps[0].meta["outcome"]["watchdog_fired"])
        self.assertGreaterEqual(dumps[0].meta["outcome"]["elapsed_ms"], 29_000)


class AbandonedStreamedBodyIsPartial(MatrixCase):
    """The sender gives up mid-body. The edge cannot dump what never arrived."""

    CAPTURE_MAX_DUMPS = 10
    # The metrics carry only the status class, so the invariant reads a
    # retryable 4xx as a drop. a45b owns the status; this case owns the dump.
    EXPECT_PERMANENT_DROP = True
    # The a45b defect, which this fault reproduces with or without a capture.
    DEFECTS = {"httpz": "answers a 4xx for the batch and leaves requests counted in flight"}

    def test_a_partial_body_gives_a_partial_dump(self):
        body = self.log_batch(STREAMED_BYTES)
        cut = len(body) // 2
        self.abandon(body, cut=cut, extra="DD-API-KEY: %s\r\nDD-EVP-ORIGIN: agent" % SECRET)
        dumps = self.captures.wait_for(1, timeout=5)
        for dump in dumps:
            check_dump(self, dump, body, err=dump.meta["outcome"]["err"], complete=False)
            self.assertIsNotNone(dump.meta["outcome"]["err"])
            # Every byte the sender sent arrived before its FIN.
            self.assertEqual(len(dump.body), cut, "the dump lost bytes the edge received")
        # A frontend that reads the whole body before it dials sends nothing
        # upstream and owes no dump. One that streams sent part of a batch and
        # owes the partial dump.
        if self.edge.frontend() == "stdio":
            self.assertEqual(len(dumps), 1, "the edge streamed part of a batch and dumped nothing")


class NothingIsCapturedForOtherOutcomes(MatrixCase):
    CAPTURE_MAX_DUMPS = 10
    FORBID_LOGS = ["upstream.failure.captured", "upstream.failure.capture.failed"]

    def test_success_retry_and_other_statuses_write_nothing(self):
        body = self.gzipped()
        self.assert_status(post(self, body), 202)
        # A retry that recovered is a success.
        self.intake.arm("close_early", count=1)
        self.assert_status(post(self, body), 202)
        for status in (401, 403, 429, 500, 503):
            self.intake.arm("status", status, count=1)
            self.assert_status(post(self, body), status)
        self.assertEqual(self.captures.wait_for(1, timeout=2), [], "only 408, 400, 413 or an error writes a dump")


class SenderLeftMidRelayIsNotCaptured(MatrixCase):
    """The intake answered; the sender was gone. That is not an upstream failure."""

    CAPTURE_MAX_DUMPS = 10
    ALLOW_PHANTOM_SUCCESS = True
    FORBID_LOGS = ["upstream.failure.captured"]

    def test_a_vanished_sender_writes_no_dump(self):
        body = self.gzipped()
        self.intake.arm("slow", 1500, count=1)
        client = self.raw(timeout=30)
        head = self.head(body_len=len(body), extra="DD-API-KEY: %s\r\nContent-Encoding: gzip" % SECRET)
        client.send(head + body)
        self.assertGreaterEqual(self.intake_saw(self.baseline_intake + 1), self.baseline_intake + 1)
        # RST, so the edge's relay write fails at once instead of filling a buffer.
        client.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        client.close()
        time.sleep(2.5)
        if self.edge.frontend() == "stdio":
            # stdio relays through the socket inside the exchange, so the
            # write fails there. httpz buffers the answer and writes it later.
            self.assert_logged("WriteFailed", "the relay never failed, so the case proved nothing")
        self.assertEqual(self.captures.dumps(), [], "a sender's disconnect is not an upstream failure")


class CaptureIsCapped(MatrixCase):
    CAPTURE_MAX_DUMPS = 2
    EXPECT_LOGS = ["upstream.failure.capture.full"]

    def test_the_cap_holds_across_a_restart(self):
        body = self.gzipped()
        streamed = gzip.compress(os.urandom(STREAMED_BYTES))
        for payload in (body, streamed, body, streamed):
            self.intake.arm("status", 408, count=1)
            self.assert_status(post(self, payload), 408)
        dumps = self.captures.wait_for(3, timeout=3)
        self.assertEqual(len(dumps), 2, "the cap is 2")
        self.assertEqual(self.case_logs().count("upstream.failure.capture.full"), 1, "warned once")

        # A restart counts the dumps already on disk.
        second = Edge(self.intake.url, self.edge_config, self.edge_env)
        try:
            self.assertIn("existing=2", second.logs())
            self.intake.arm("status", 408, count=1)
            headers = {"Content-Type": "application/json", **AGENT_HEADERS}
            response = requests.post(second.url + "/api/v2/logs", data=body, headers=headers, timeout=60)
            self.assert_status(response, 408)
            self.assertIn("upstream.failure.capture.full", second.logs(), "the second edge did not try")
            self.assertEqual(len(self.captures.wait_for(3, timeout=2)), 2, "a restart re-armed the capture")
        finally:
            second.stop()


class UnusableDirectoryKeepsServing(MatrixCase):
    EDGE_ENV = {"TERO_FAILURE_CAPTURE_DIR": "/dev/null/failure-capture"}
    FORBID_LOGS = ["upstream.failure.captured"]

    def test_the_data_plane_is_unaffected(self):
        # A startup line, so it is outside `case_logs`.
        self.assertIn("failure.capture.unavailable", self.edge.logs())
        body = self.gzipped()
        self.assert_status(post(self, body), 202)
        self.intake.arm("status", 408, count=1)
        self.assert_status(post(self, body), 408)
