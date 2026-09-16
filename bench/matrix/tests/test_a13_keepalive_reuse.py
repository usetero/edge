"""A13: many requests on one connection, the way an agent actually sends."""

import requests

from harness import MatrixCase


class KeepaliveReuse(MatrixCase):
    def test_one_connection_serves_many_requests(self):
        session = requests.Session()
        try:
            for _ in range(50):
                response = session.post(
                    self.edge.url + "/api/v2/logs",
                    json=[{"message": "keepalive"}],
                    timeout=30,
                )
                self.assertEqual(response.status_code, 202)
        finally:
            session.close()

        self.assertGreaterEqual(self.intake_saw(50), 50)
        if self.frontend == "stdio":
            # 50 requests, but the sender opened one connection.
            self.assertLessEqual(self.metric_delta("edge_connections_total"), 4)
