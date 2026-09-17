"""B25: the intake answers a redirect.

Redirects are unhandled by design, so the sender gets it verbatim rather than
the edge chasing it. A wrong scheme in `upstream_url` looks exactly like this,
so the status must survive intact for anyone reading agent logs.
"""

from harness import MatrixCase


class Redirect(MatrixCase):
    ALLOW_PHANTOM_SUCCESS = True

    def test_a_redirect_is_relayed_verbatim(self):
        self.intake.arm("redirect", count=1)
        response = self.post_logs(timeout=30, allow_redirects=False)

        self.assertEqual(response.status_code, 308, repr(response))
        self.assertIn("location", {k.lower() for k in response.headers})
