"""B26: the target the intake receives.

Agents put tags, and sometimes credentials, in the query. A base path in
`upstream_url` is an ordinary proxy configuration. Both must arrive byte for
byte.
"""

from harness import MatrixCase


class QueryFidelity(MatrixCase):
    def test_the_query_survives_byte_for_byte(self):
        target = "/api/v2/logs?ddtags=env%3Aprod%2Cteam%3Aplatform&dd-api-key=abc123&x=a+b"
        response = self.post_logs(path=target, timeout=30)
        self.assert_status(response, 202)
        self.assertEqual(self.intake_saw(1), 1)
        self.assertEqual(
            self.intake.stats().get("last_target"),
            target,
            "the intake received a different target than the sender wrote",
        )
