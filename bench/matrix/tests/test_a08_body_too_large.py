"""A08: a batch above max_body_size."""

from harness import MatrixCase


class BodyTooLarge(MatrixCase):
    EDGE_CONFIG = {"max_body_size": 16384}

    def test_oversize_body_is_rejected(self):
        response = self.post_raw_body(b"x" * 65536)
        self.assert_status(response, 413, "an oversize body must be refused")
        self.assertEqual(self.intake_saw(1, timeout=2), 0, "an oversize body reached the intake")
