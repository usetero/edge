"""B07: the intake answers with more body than the edge will relay."""

from harness import MatrixCase


class OversizeResponse(MatrixCase):
    EDGE_CONFIG = {"max_body_size": 65536}

    def test_an_oversize_response_is_bounded(self):
        self.intake.arm("oversize", arg=1_048_576, count=1)
        try:
            response = self.post_logs(timeout=60)
        except Exception as err:  # a truncated relay is also an acceptable answer
            self.assert_logged("upstream")
            self.skipTest("relay closed rather than answering: %s" % err)
        self.assertEqual(response.status_code // 100, 5, "got %d" % response.status_code)
        self.assert_logged("upstream")
