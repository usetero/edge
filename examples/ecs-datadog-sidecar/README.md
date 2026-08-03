# Tero Edge as a Datadog log-proxy sidecar (ECS / Fargate)

Run Edge next to the Datadog Agent in the same ECS task. The Agent sends logs to
Edge over `127.0.0.1`; Edge applies policies and forwards to Datadog. APM (8126)
and DogStatsD (8125) keep going direct — only logs pass through Edge.

```
containers in task ──► datadog-agent ──► tero-edge (127.0.0.1:8080) ──► Datadog logs intake
```

In `awsvpc`/Fargate networking all containers in a task share one network
namespace, so they reach each other over the loopback interface — no
`hostIP`/`hostPort` plumbing is needed (unlike the Kubernetes DaemonSet setup).

<!-- prettier-ignore -->
> **Use `127.0.0.1`, not `localhost`.** Edge binds `0.0.0.0`, which is IPv4-only.
> `localhost` can resolve to `::1` first, and the connection is then refused.

## No config file needed

The `ghcr.io/usetero/edge-datadog` image ships a default config baked in. You
only set environment variables:

- `TERO_API_KEY` — **required** for policy sync from Tero (from Secrets Manager
  / SSM).
- `TERO_UPSTREAM_URL` / `TERO_METRICS_URL` — override only if you're **not** on
  US1.

The default targets US1 (`agent-http-intake.logs.datadoghq.com` /
`api.datadoghq.com`), listens on `0.0.0.0:8080`, and syncs policies from
`https://sync.usetero.com`. For other regions set:

| Region | `TERO_UPSTREAM_URL`                                | `TERO_METRICS_URL`              |
| ------ | -------------------------------------------------- | ------------------------------- |
| US3    | `https://agent-http-intake.logs.us3.datadoghq.com` | `https://api.us3.datadoghq.com` |
| US5    | `https://agent-http-intake.logs.us5.datadoghq.com` | `https://api.us5.datadoghq.com` |
| EU     | `https://agent-http-intake.logs.datadoghq.eu`      | `https://api.datadoghq.eu`      |
| AP1    | `https://agent-http-intake.logs.ap1.datadoghq.com` | `https://api.ap1.datadoghq.com` |

Any config field is overridable via a `TERO_`-prefixed env var (e.g.
`TERO_LISTEN_PORT`, `TERO_LOG_LEVEL`). See
https://docs.usetero.com/edge/edge-reference/config.

## Terraform: add the Edge sidecar

```hcl
edge_container = {
  name       = "tero-edge"
  image      = "ghcr.io/usetero/edge-datadog:latest"
  cpu        = 0
  essential  = true
  portMappings = [
    { "containerPort" : 8080, "protocol" : "tcp" }
  ]
  environment = [
    { "name" : "TERO_LOG_LEVEL", "value" : "info" }
    # Non-US1 only:
    # { "name" : "TERO_UPSTREAM_URL", "value" : "https://agent-http-intake.logs.datadoghq.eu" },
    # { "name" : "TERO_METRICS_URL", "value" : "https://api.datadoghq.eu" }
  ]
  secrets = [
    # API key for policy sync — from SSM Parameter Store or Secrets Manager
    { "name" : "TERO_API_KEY", "valueFrom" : aws_ssm_parameter.tero_api_key.arn }
  ]
  logConfiguration = {
    logDriver = "awslogs"
    options = {
      "awslogs-group"         = aws_cloudwatch_log_group.ecs_log_group.name
      "awslogs-region"        = var.region
      "awslogs-stream-prefix" = "tero-edge"
      "mode"                  = "non-blocking"
    }
  }
  healthCheck = {
    command     = ["CMD-SHELL", "wget -qO- http://127.0.0.1:8080/_health || exit 1"]
    interval    = 30
    timeout     = 5
    retries     = 3
    startPeriod = 15
  }
  mountPoints = [], volumesFrom = [], systemControls = []
}
```

Add `edge_container` to the task's `container_definitions` list alongside the
Datadog Agent container.

## Point the Datadog Agent's logs at Edge

Add these to the **existing Datadog Agent container** `environment` block:

```hcl
{ "name" : "DD_LOGS_ENABLED",            "value" : "true" },
{ "name" : "DD_LOGS_CONFIG_USE_HTTP",    "value" : "true" },
{ "name" : "DD_LOGS_CONFIG_LOGS_NO_SSL", "value" : "true" },  # Edge listens plain HTTP
{ "name" : "DD_LOGS_CONFIG_LOGS_DD_URL", "value" : "127.0.0.1:8080" }
```

`DD_LOGS_CONFIG_LOGS_DD_URL` takes `host:port` (no scheme). The Agent POSTs logs
over plain HTTP to Edge; Edge re-forwards to the upstream over HTTPS.

## FireLens / Fluent Bit instead of the Agent

If your task ships logs with the `awsfirelens` log driver, point the `datadog`
output at Edge. The log-router container is in the same task, so it reaches Edge
over loopback the same way.

```hcl
logConfiguration = {
  logDriver = "awsfirelens"
  options = {
    "Name"           = "datadog"
    "apikey"         = local.dd_api_key
    "compress"       = "gzip"
    "Host"           = "127.0.0.1"  # hostname only — no port
    "Port"           = "8080"
    "TLS"            = "off"        # Edge listens plain HTTP
    "dd_service"     = var.service
    "dd_source"      = "ecs-fargate"
    "dd_message_key" = "log"
    "dd_tags"        = "env:${var.environment}"
    "provider"       = "ecs"
    "retry_limit"    = "10"
  }
}
```

Three things bite here:

1. **`Host` is a hostname only.** Fluent Bit's `datadog` output takes `Host` and
   `Port` as separate properties. Writing `"Host" = "127.0.0.1:8080"` makes it
   resolve the whole string as a DNS name and fail with
   `getaddrinfo(host='127.0.0.1:8080', err=4): Domain name not found`.
2. **`TLS` must be `off`.** Edge listens plain HTTP, so the Agent's
   `DD_LOGS_CONFIG_LOGS_NO_SSL` equivalent here is `TLS = "off"`.
3. **Fluent Bit starts before Edge is ready.** With a low `retry_limit` you lose
   the first chunks to `cannot be retried`. Raise it, and gate startup on the
   **log-router** container:

   ```hcl
   dependsOn = [{ containerName = "tero-edge", condition = "HEALTHY" }]
   ```

Fluent Bit batches decompress well past Edge's 1 MB default body cap, so if
payloads start getting rejected raise `TERO_MAX_BODY_SIZE` and
`TERO_MAX_DECODED_BYTES`.

## Overriding the defaults with env vars

Every scalar config field is settable as a `TERO_`-prefixed env var. The name is
the field path in `SCREAMING_SNAKE_CASE`, with nested fields joined by `_`
(`service.namespace` → `TERO_SERVICE_NAMESPACE`). Env vars win over the baked
config file.

| Variable                 | Field               | Default in `edge-datadog`                      |
| ------------------------ | ------------------- | ---------------------------------------------- |
| `TERO_LISTEN_ADDRESS`    | `listen_address`    | `0.0.0.0`                                      |
| `TERO_LISTEN_PORT`       | `listen_port`       | `8080`                                         |
| `TERO_UPSTREAM_URL`      | `upstream_url`      | `https://agent-http-intake.logs.datadoghq.com` |
| `TERO_METRICS_URL`       | `metrics_url`       | `https://api.datadoghq.com`                    |
| `TERO_LOGS_URL`          | `logs_url`          | unset                                          |
| `TERO_LOG_LEVEL`         | `log_level`         | `info`                                         |
| `TERO_SERVICE_NAME`      | `service.name`      | `edge`                                         |
| `TERO_SERVICE_NAMESPACE` | `service.namespace` | `production`                                   |
| `TERO_SERVICE_VERSION`   | `service.version`   | `latest`                                       |
| `TERO_MAX_BODY_SIZE`     | `max_body_size`     | `1048576`                                      |
| `TERO_MAX_DECODED_BYTES` | `max_decoded_bytes` | unset (falls back to `max_body_size`)          |
| `TERO_MAX_CONNECTIONS`   | `max_connections`   | `256`                                          |
| `TERO_WORKER_COUNT`      | `worker_count`      | unset (1)                                      |
| `TERO_THREAD_POOL_COUNT` | `thread_pool_count` | unset (32)                                     |

`policy_providers` is a list and cannot be set this way — override the config
file instead. Full reference, including value substitution and the remaining
fields: https://docs.usetero.com/edge/edge-reference/config

## Managing policies locally instead of Tero sync

The default syncs policies from Tero. To manage them locally instead, supply
your own `config.json` with a file provider and mount it over `/app/config.json`
(EFS volume, or bake a thin image `FROM ghcr.io/usetero/edge-datadog`). See
https://docs.usetero.com/edge/policy-reference/log-filter for policy options.

## Verify

- Edge container logs show incoming traffic and `policy`-related lines at
  startup.
- `wget -qO- http://localhost:8080/_health` from within the task returns
  healthy.
- Logs still land in Datadog, minus whatever your policies drop.
