# Tero Edge as a Datadog log-proxy sidecar (ECS / Fargate)

Run Edge next to the Datadog Agent in the same ECS task. The Agent sends logs to
Edge over `localhost`; Edge applies policies and forwards to Datadog. APM (8126)
and DogStatsD (8125) keep going direct — only logs pass through Edge.

```
containers in task ──► datadog-agent ──► tero-edge (127.0.0.1:8080) ──► Datadog logs intake
```

In `awsvpc`/Fargate networking all containers in a task share `localhost`, so no
`hostIP`/`hostPort` plumbing is needed (unlike the Kubernetes DaemonSet setup).

## Files

- `config.json` — Edge config. Policies sync from Tero over HTTPS (recommended).
- `policies.json` — only needed if you use the **file provider** instead (see below).

Set `upstream_url` / `metrics_url` for your Datadog region:

| Region | `upstream_url` | `metrics_url` |
|--------|----------------|---------------|
| US1 | `https://agent-http-intake.logs.datadoghq.com` | `https://api.datadoghq.com` |
| US3 | `https://agent-http-intake.logs.us3.datadoghq.com` | `https://api.us3.datadoghq.com` |
| US5 | `https://agent-http-intake.logs.us5.datadoghq.com` | `https://api.us5.datadoghq.com` |
| EU  | `https://agent-http-intake.logs.datadoghq.eu` | `https://api.datadoghq.eu` |
| AP1 | `https://agent-http-intake.logs.ap1.datadoghq.com` | `https://api.ap1.datadoghq.com` |

## Getting the config into the container

Fargate has no ConfigMap. Bake `config.json` into a thin image — reproducible and
no extra infra:

```dockerfile
# Dockerfile
FROM ghcr.io/usetero/edge-datadog:latest
COPY config.json /etc/tero/config.json
# For the file provider, also: COPY policies.json /etc/tero/policies.json
```

`${TERO_API_KEY}` in `config.json` is substituted at startup from the env var, so
the secret never lives in the image.

> Alternative: mount an EFS volume at `/etc/tero` and drop the files there instead
> of baking an image.

## Terraform: add the Edge sidecar

```hcl
edge_container = {
  name       = "tero-edge"
  image      = "<your-account>.dkr.ecr.<region>.amazonaws.com/tero-edge:latest" # image above
  cpu        = 0
  essential  = true
  command    = ["/etc/tero/config.json"]
  portMappings = [
    { "containerPort" : 8080, "protocol" : "tcp" }
  ]
  environment = [
    { "name" : "TERO_LOG_LEVEL", "value" : "info" }
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
over plain HTTP to Edge; Edge re-forwards to `upstream_url` over HTTPS.

## Using the file provider instead of Tero sync

To manage policies locally instead of syncing from Tero, bake `policies.json`
into the image and swap the `policy_providers` block in `config.json` to:

```json
"policy_providers": [
  { "id": "file", "type": "file", "path": "/etc/tero/policies.json" }
]
```

`policies.json` in this directory drops `DEBUG` logs, drops `nginx`-sourced logs,
and force-keeps errors — adjust to taste. See
https://docs.usetero.com/edge/policy-reference/log-filter for all options.

## Verify

- Edge container logs show incoming traffic and `policy`-related lines at startup.
- `wget -qO- http://localhost:8080/_health` from within the task returns healthy.
- Logs still land in Datadog, minus whatever your policies drop.
