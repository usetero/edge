"""A22: a health check that is not a GET, and a proxy-form target.

`/_health` is registered GET-only, so any other method falls through to the
wildcard passthrough and is forwarded to the intake. An ALB or ECS check
configured for HEAD therefore does not test the edge at all: it tests Datadog,
and it fails whenever the intake is unreachable. That is the same failure mode
as the incident this suite exists for.
"""

import requests

from harness import MatrixCase


class HealthMethods(MatrixCase):
    DEFECTS = {
        "stdio": "HEAD and POST /_health fall through to the passthrough and are forwarded",
        "httpz": "HEAD and POST /_health fall through to the passthrough and are forwarded",
    }

    def test_head_health_is_answered_locally(self):
        before = self.intake.requests_seen()
        try:
            status = requests.head(self.edge.url + "/_health", timeout=10).status_code
        except requests.exceptions.RequestException as err:
            self.fail("HEAD /_health was not answered: %s" % type(err).__name__)
        self.assertEqual(status, 200, "a HEAD probe must answer from the edge")
        self.assertEqual(
            self.intake.requests_seen(),
            before,
            "a health probe was forwarded to the intake",
        )


class HealthMethodsPost(MatrixCase):
    DEFECTS = {
        "stdio": "POST /_health is forwarded to the intake",
        "httpz": "POST /_health is forwarded to the intake",
    }

    def test_post_health_does_not_reach_the_intake(self):
        before = self.intake.requests_seen()
        requests.post(self.edge.url + "/_health", data=b"", timeout=10)
        self.assertEqual(
            self.intake.requests_seen(),
            before,
            "POST /_health was forwarded to the intake as passthrough traffic",
        )


class AbsoluteFormTarget(MatrixCase):
    DEFECTS = {"stdio": "forwards the absolute-form target upstream as a path"}

    def test_absolute_form_target_is_not_forwarded_verbatim(self):
        before = self.intake.requests_seen()
        with self.raw(timeout=20) as client:
            client.send(
                b"GET http://example.com/_health HTTP/1.1\r\nHost: x\r\n"
                b"Connection: close\r\n\r\n"
            )
            answer = client.read_response()
        # Either we answer health locally or we refuse it. Forwarding a
        # mangled target to the intake is the one wrong answer.
        self.assertEqual(
            self.intake.requests_seen(),
            before,
            "an absolute-form target was forwarded to the intake (status %s)" % answer.status,
        )
