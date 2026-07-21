# Tero Edge as a Datadog log-proxy sidecar (ECS / Fargate)

Run Edge next to the Datadog Agent in the same ECS task. The Agent sends logs to
Edge over `localhost`; Edge applies policies and forwards to Datadog. APM (8126)
and DogStatsD (8125) keep going direct — only logs pass through Edge.

```
containers in task ──► datadog-agent ──► tero-edge (127.0.0.1:8080) ──► Datadog logs intake
```

In `awsvpc`/Fargate networking all containers in a task share `localhost`, so no
`hostIP`/`hostPort` plumbing is needed (unlike the Kubernetes DaemonSet setup).

## No config file needed

The `ghcr.io/usetero/edge-datadog` image ships a default config baked in. You
only set environment variables:

- `TERO_API_KEY` — **required** for policy sync from Tero (from Secrets Manager / SSM).
- `TERO_UPSTREAM_URL` / `TERO_METRICS_URL` — override only if you're **not** on US1.

The default targets US1 (`agent-http-intake.logs.datadoghq.com` /
`api.datadoghq.com`), listens on `0.0.0.0:8080`, and syncs policies from
`https://sync.usetero.com`. For other regions set:

| Region | `TERO_UPSTREAM_URL` | `TERO_METRICS_URL` |
|--------|---------------------|--------------------|
| US3 | `https://agent-http-intake.logs.us3.datadoghq.com` | `https://api.us3.datadoghq.com` |
| US5 | `https://agent-http-intake.logs.us5.datadoghq.com` | `https://api.us5.datadoghq.com` |
| EU  | `https://agent-http-intake.logs.datadoghq.eu` | `https://api.datadoghq.eu` |
| AP1 | `https://agent-http-intake.logs.ap1.datadoghq.com` | `https://api.ap1.datadoghq.com` |

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
    command     = ["CMD-SHELL", "wget -qO- http://localhost:8080/_health || exit 1"]
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
{ "name" : "DD_LOGS_CONFIG_LOGS_DD_URL", "value" : "localhost:8080" }
```

`DD_LOGS_CONFIG_LOGS_DD_URL` takes `host:port` (no scheme). The Agent POSTs logs
over plain HTTP to Edge; Edge re-forwards to the upstream over HTTPS.

## Managing policies locally instead of Tero sync

The default syncs policies from Tero. To manage them locally instead, supply your
own `config.json` with a file provider and mount it over `/app/config.json` (EFS
volume, or bake a thin image `FROM ghcr.io/usetero/edge-datadog`). See
https://docs.usetero.com/edge/policy-reference/log-filter for policy options.

## Verify

- Edge container logs show incoming traffic and `policy`-related lines at startup.
- `wget -qO- http://localhost:8080/_health` from within the task returns healthy.
- Logs still land in Datadog, minus whatever your policies drop.
