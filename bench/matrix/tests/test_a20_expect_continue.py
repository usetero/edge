"""A20: a sender that waits for 100-continue before it sends the body.

A strict client holds the body until the interim answer arrives. If the edge
never sends it, the sender stalls until its own timeout and the batch is late
or lost. `Expect` is also hop-by-hop: it must not travel to the intake.
"""

from harness import MatrixCase


class ExpectContinue(MatrixCase):
    def test_the_interim_answer_arrives_then_the_batch_lands(self):
        body = b'[{"message":"expect"}]'
        with self.raw(timeout=30) as client:
            client.send(self.head(body_len=len(body), extra="Expect: 100-continue"))
            interim = client.read_response()
            self.assertIsNotNone(interim.status, "no interim answer, so a strict sender stalls")
            if interim.status == 100:
                client.send(body)
                final = client.read_response()
                self.assertEqual(final.status, 202, repr(final))
            else:
                # Some servers answer the final status directly, which is also
                # workable as long as the sender is not left waiting.
                self.assertLess(interim.seconds, 5)

        self.assertGreaterEqual(self.intake_saw(1), 1, "the batch never reached the intake")
