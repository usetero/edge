"""B08: the intake answers with bytes that are not HTTP."""

from harness import MatrixCase


class GarbageResponse(MatrixCase):
    def test_garbage_from_the_intake_is_a_bad_gateway(self):
        self.intake.arm("garbage", count=1)
        response = self.post_logs(timeout=60)

        self.assertEqual(response.status_code // 100, 5, "got %d" % response.status_code)
        self.assert_logged("upstream")
