"""B30: the failure capture writes a dump an engineer can replay.

On a relayed 408, or on an error out of the upstream exchange, the edge writes
the outgoing body and its metadata to `TERO_FAILURE_CAPTURE_DIR`. What the
customer's engineer needs from a dump:

- the body is the bytes the edge sent, still compressed: equal to what the
  intake received, and not the inbound body when a policy changed the batch;
- the metadata says what happened (status or error, phase, attempts, the
  watchdog) and never holds a credential;
- a dump that cannot hold the whole body says so;
- a success, a retry that recovered, and a status other than 408 write nothing;
- the directory never grows past its cap, across restarts too;
- a capture that cannot open its directory never stops the data plane.
"""

import gzip
import json
import os

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


def post(case, body, query="", headers=None, timeout=60.0):
    merged = dict(AGENT_HEADERS)
    merged.update(headers or {})
    return case.post_raw_body(body, path="/api/v2/logs" + query, headers=merged, timeout=timeout)


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
        for status in (400, 429, 500, 503):
            self.intake.arm("status", status, count=1)
            self.assert_status(post(self, body), status)
        self.intake.arm("reject_early", count=1)
        self.assert_status(post(self, body), 400)
        self.assertEqual(self.captures.wait_for(1, timeout=2), [], "only a 408 or an error writes a dump")


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
