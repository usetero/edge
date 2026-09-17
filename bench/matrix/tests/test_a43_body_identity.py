"""A43: what the intake receives, byte for byte.

A customer's batch is their data. If the edge changes nothing about a record,
the intake must receive the bytes the agent sent — not a re-serialized,
re-ordered or re-escaped version of them. Three regimes, and the contract
differs between them:

  * No policies loaded. The router plans a passthrough, so the body is
    forwarded untouched. Byte identity.
  * Policies loaded, and no record changes. The prefilter reports no change and
    the frontend forwards the original body, so again byte identity. This is
    the fast path a production policy set takes most of the time.
  * Policies loaded, and a record is dropped. Here the array is re-framed:
    every surviving element keeps its own bytes exactly, and the separators
    between elements are re-emitted canonically, so whitespace between
    elements does not survive. That is a deliberate difference, and this case
    pins it down rather than leaving it to be discovered.

The junk in the payload is the point. Unicode escapes, a tab inside a string,
duplicate keys, an exponent, a huge integer, deep nesting, an empty object and
a null all round-trip through a JSON library differently. Only untouched bytes
survive all of them.
"""

import json

from harness import MatrixCase

#: Formatting and values a re-serializing proxy would quietly change.
JUNK_BATCH = (
    b'[\n  {"ddsource":"matrix","message":"first",'
    b'"unicode":"caf\\u00e9 \\u2013 \\ud83d\\ude00","tabbed":"a\\tb",'
    b'"dupe":1,"dupe":2,"exp":1.0e+3,"big":10000000000000000000000,'
    b'"trailing_zero":1.500,"nested":{"a":{"b":{"c":[1,{"d":null}]}}},'
    b'"empty":{},"nothing":null,"spaced"  :  "  keep  me  "},\n'
    b'  {"ddsource":"matrix","message":"second","drop_me":true}\n]'
)

KEEP_ALL = {
    "policies": [
        {
            "id": "keep-all",
            "name": "keep-all",
            "log": {"match": [{"log_field": "body", "regex": ".+"}], "keep": "all"},
        }
    ]
}

DROP_SECOND = {
    "policies": [
        {
            "id": "drop-second",
            "name": "drop-second",
            "log": {"match": [{"log_field": "body", "regex": "^second$"}], "keep": "none"},
        }
    ]
}


class BodyIdentityWithoutPolicies(MatrixCase):
    """Nothing is loaded, so nothing may read or rewrite the batch."""

    def test_the_intake_receives_the_bytes_the_sender_sent(self):
        self.intake.capture_start("a43-none")
        response = self.post_raw_body(JUNK_BATCH)
        self.assert_status(response, 202, "a well-formed batch must be accepted")
        bodies = self.intake.capture_stop()
        self.assertEqual(1, len(bodies), "the intake recorded %d bodies" % len(bodies))
        self.assertEqual(JUNK_BATCH, bodies[0], "the forwarded batch is not the batch we sent")


class BodyIdentityWhenNoRecordChanges(MatrixCase):
    """Policies are loaded and keep everything, so the original body forwards."""

    EDGE_POLICIES = KEEP_ALL

    def test_a_batch_no_policy_changes_is_forwarded_untouched(self):
        self.intake.capture_start("a43-keep")
        response = self.post_raw_body(JUNK_BATCH)
        self.assert_status(response, 202, "a kept batch must be accepted")
        bodies = self.intake.capture_stop()
        self.assertEqual(1, len(bodies), "the intake recorded %d bodies" % len(bodies))
        self.assertEqual(
            JUNK_BATCH,
            bodies[0],
            "a batch no policy changed must reach the intake unmodified",
        )


class ElementsSurviveAReframe(MatrixCase):
    """One record is dropped, so the array is re-framed around the survivors."""

    EDGE_POLICIES = DROP_SECOND
    ALLOW_PHANTOM_SUCCESS = True

    def test_the_surviving_element_keeps_its_own_bytes(self):
        self.intake.capture_start("a43-drop")
        response = self.post_raw_body(JUNK_BATCH)
        self.assert_status(response, 202, "a partly dropped batch is still a success")
        bodies = self.intake.capture_stop()
        self.assertEqual(1, len(bodies), "the intake recorded %d bodies" % len(bodies))
        forwarded = bodies[0]

        # The dropped record is gone, and the batch is still valid JSON.
        records = json.loads(forwarded)
        self.assertEqual(1, len(records), "expected one surviving record: %r" % forwarded)
        self.assertEqual("first", records[0]["message"])

        # The survivor's bytes are copied, not re-serialized: the element as it
        # appeared in the request is a substring of what the intake received.
        first_element = JUNK_BATCH[JUNK_BATCH.index(b"{") : JUNK_BATCH.index(b"},\n") + 1]
        self.assertIn(
            first_element,
            forwarded,
            "the surviving element was rewritten rather than copied:\n%r" % forwarded,
        )
