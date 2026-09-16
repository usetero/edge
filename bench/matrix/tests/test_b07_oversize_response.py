"""B07: the intake answers with more body than the edge will relay."""

from harness import MatrixCase


class OversizeResponse(MatrixCase):
    EDGE_CONFIG = {"max_body_size": 65536}

    def test_an_oversize_response_is_bounded(self):
        self.intake.arm("oversize", arg=1_048_576, count=1)
        status = None
        try:
            status = self.post_logs(timeout=60).status_code
        except Exception:
            status = None  # the relay closed rather than answering

        # Either answer is honest. What must not happen is a clean 2xx that
        # hides a response the edge refused to carry.
        if status is not None:
            self.assertEqual(status // 100, 5, "an oversize relay reported %d" % status)
        self.assert_logged("upstream")
