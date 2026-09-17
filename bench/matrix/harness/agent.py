"""How the Datadog agent treats the status we answer.

From `comp/logs-library/client/http/destination.go` in DataDog/datadog-agent
(`sendPost`):

    if resp.StatusCode == 400 || 401 || 403 || 413 {
        tlmDropped.Inc()          // "payloads dropped because of
        return errClient          //  unrecoverable errors"
    } else if resp.StatusCode > 400 {
        return client.NewRetryableError(errServer)
    }

So the agent **drops the payload permanently** on 400, 401, 403 and 413, and
**retries with exponential backoff** on every other error status and on
transport failures. The backoff blocks that pipeline while it waits.

Two consequences the suite cares about:

- Answering a drop-class status for a batch the intake never received is
  permanent data loss, not a retryable hiccup. That is the most severe thing
  the edge can do.
- Answering a retry-class status for a request that can never succeed (a
  header flood, say) costs an unbounded retry loop, whether we say 431 or 502.
  The choice between them is about diagnosis, not about agent behaviour.
"""

#: The agent discards the payload and never sends it again.
DROPS_PAYLOAD = frozenset({400, 401, 403, 413})


def drops_payload(status: int) -> bool:
    return status in DROPS_PAYLOAD


def retries(status: int) -> bool:
    return status > 400 and status not in DROPS_PAYLOAD
