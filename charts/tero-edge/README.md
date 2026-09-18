# tero-edge

Tero Edge Helm chart for Kubernetes.

This chart deploys `ghcr.io/usetero/edge` as a `DaemonSet`, mounts
`config.json` + `policies.json` from a ConfigMap, and optionally configures HTTP
policy sync with API-key auth.

## Install

```bash
helm upgrade --install tero-edge ./charts/tero-edge \
  -n tero-system --create-namespace
```

## Install From OCI (GHCR)

```bash
helm upgrade --install tero-edge oci://ghcr.io/usetero/charts/tero-edge \
  --version <chart-version> \
  -n tero-system --create-namespace
```

## Install From Helm Repository (GitHub Pages)

```bash
helm repo add tero-edge https://usetero.github.io/edge/
helm repo update
helm upgrade --install tero-edge tero-edge/tero-edge \
  --version <chart-version> \
  -n tero-system --create-namespace
```

## Quick Start

Example values using top-level `tero` config and multiline JSON policies:

```yaml
tero:
  url: https://control.tero.dev
  apiKey: your-api-key

policiesJSON:
  - |
    {
      "id": "drop-debug-logs",
      "name": "drop-debug-logs",
      "enabled": true,
      "log": {
        "match": [{ "log_field": "severity_text", "regex": "DEBUG" }],
        "keep": "none"
      }
    }
```

Then:

```bash
helm upgrade --install tero-edge ./charts/tero-edge \
  -n tero-system --create-namespace \
  -f values.yaml
```

## Authentication

If `tero.url` is set, HTTP policy provider is automatically configured at:

`<tero.url>/v1/policy/sync`

Provide auth either via:

1. `tero.apiKey` (chart creates a Secret), or
2. `tero.existingSecret.name` + `tero.existingSecret.key`

## Values

| Key                                 | Type   | Default                                        | Description                                                   |
| ----------------------------------- | ------ | ---------------------------------------------- | ------------------------------------------------------------- |
| `image.repository`                  | string | `ghcr.io/usetero/edge`                         | Container image repository                                    |
| `image.tag`                         | string | `""`                                           | Image tag (defaults to chart `appVersion`)                    |
| `image.pullPolicy`                  | string | `IfNotPresent`                                 | Image pull policy                                             |
| `container.args`                    | list   | `[/etc/tero/config.json]`                      | Container args                                                |
| `container.port`                    | int    | `8080`                                         | Container port                                                |
| `container.hostPort.enabled`        | bool   | `true`                                         | Enable hostPort                                               |
| `container.hostPort.port`           | int    | `8080`                                         | Host port                                                     |
| `resources.requests.cpu`            | string | `50m`                                          | CPU request                                                   |
| `resources.requests.memory`         | string | `256Mi`                                        | Memory request (see Sizing)                                   |
| `resources.limits.cpu`              | string | `200m`                                         | CPU limit                                                     |
| `resources.limits.memory`           | string | `768Mi`                                        | Memory limit (see Sizing)                                     |
| `service.enabled`                   | bool   | `false`                                        | Create Service                                                |
| `service.type`                      | string | `ClusterIP`                                    | Service type                                                  |
| `service.port`                      | int    | `8080`                                         | Service port                                                  |
| `daemonset.updateStrategy.type`     | string | `RollingUpdate`                                | DaemonSet update strategy                                     |
| `tero.url`                          | string | `""`                                           | Tero control plane base URL                                   |
| `tero.apiKey`                       | string | `""`                                           | Inline API key (creates Secret)                               |
| `tero.existingSecret.name`          | string | `""`                                           | Existing Secret name for API key                              |
| `tero.existingSecret.key`           | string | `api-key`                                      | Existing Secret key containing API key                        |
| `config.listenAddress`              | string | `0.0.0.0`                                      | Edge listen address                                           |
| `config.listenPort`                 | int    | `8080`                                         | Edge listen port                                              |
| `config.upstreamUrl`                | string | `https://agent-http-intake.logs.datadoghq.com` | Default upstream URL                                          |
| `config.metricsUrl`                 | string | `https://api.datadoghq.com`                    | Metrics upstream URL                                          |
| `config.logLevel`                   | string | `info`                                         | Log level                                                     |
| `config.maxBodySize`                | int    | `1572864`                                      | Raw request body cap as received on the wire                  |
| `config.maxConnections`             | int    | `256`                                          | Max concurrent connections; also caps workerCount             |
| `config.maxDecodedBytes`            | int    | `null`                                         | Post-decompression ceiling (null = 16 MiB, min maxBodySize)   |
| `config.workerCount`                | int    | `null`                                         | httpz build only; inert on the shipped frontend               |
| `config.threadPoolCount`            | int    | `null`                                         | httpz build only; inert on the shipped frontend               |
| `config.service.name`               | string | `""`                                           | Service name sent on policy sync (omitted if empty)           |
| `config.service.namespace`          | string | `""`                                           | Service namespace sent on policy sync (omitted if empty)      |
| `config.service.version`            | string | `""`                                           | Service version sent on policy sync (omitted if empty)        |
| `config.service.resourceAttributes` | list   | `[]`                                           | OTel resource attributes (`{key, value}`) sent on policy sync |
| `config.service.labels`             | list   | `[]`                                           | Free-form labels (`{key, value}`) sent on policy sync         |
| `config.fileProvider.enabled`       | bool   | `true`                                         | Enable file policy provider                                   |
| `config.fileProvider.id`            | string | `file`                                         | File provider ID                                              |
| `config.fileProvider.path`          | string | `/etc/tero/policies.json`                      | File policy path                                              |
| `config.extraPolicyProviders`       | list   | `[]`                                           | Additional raw policy providers                               |
| `policiesJSON`                      | list   | `[]`                                           | List of raw JSON policy objects (supports multiline strings)  |
| `extraEnv`                          | list   | `[]`                                           | Extra container env vars                                      |
| `extraVolumes`                      | list   | `[]`                                           | Extra pod volumes                                             |
| `extraVolumeMounts`                 | list   | `[]`                                           | Extra container volume mounts                                 |
| `nodeSelector`                      | object | `{}`                                           | Node selector                                                 |
| `tolerations`                       | list   | `[{'operator':'Exists'}]`                      | Pod tolerations                                               |
| `affinity`                          | object | `{}`                                           | Pod affinity                                                  |
| `podAnnotations`                    | object | `{}`                                           | Pod annotations                                               |
| `podLabels`                         | object | `{}`                                           | Pod labels                                                    |
| `serviceAccount.create`             | bool   | `true`                                         | Create a service account                                      |
| `serviceAccount.name`               | string | `""`                                           | Service account name override                                 |
| `serviceAccount.automount`          | bool   | `true`                                         | Automount SA token                                            |

## Sizing

Memory tracks the connections that are live right now. The default frontend
gives each connection its own task, so a pod's footprint follows peak
concurrency and not request rate, body size or thread count:

```
memory ~= 8 MiB + 0.9 MiB x peak concurrent connections
```

Measured on the shipped frontend: 21 MiB at 16 live connections, 65 MiB at 64,
and 229 MiB at 256. A sender holds its connection open between batches, so one
agent that pushes 10 requests/sec and one that pushes 1000 cost the same slot.

| peak live connections | approx memory | suggested limit |
| --------------------- | ------------- | --------------- |
| 16                    | 21 MiB        | 64Mi            |
| 64                    | 65 MiB        | 128Mi           |
| 256                   | 229 MiB       | 384Mi           |
| 512                   | ~470 MiB      | 768Mi           |

The first three rows are measured. The fourth extends the formula past the
range we have measured, so leave more headroom there than the arithmetic asks
for.

`maxConnections` is a ceiling, not a reservation. A slot reserves 64 KiB of
address space and commits a page only when a sender lands on it, so raising the
cap well above today's peak costs almost nothing. Set it to roughly four times
the peak you see on `edge_connections_active`, and alert on
`edge_connections_active / edge_connections_max > 0.8` for lead time.

The shipped `resources` block carries headroom above the 256-connection figure
on purpose: a policy route also holds a `maxBodySize` body buffer and a
streaming pump per runtime thread, which the connection formula above does not
count.

### `threadPoolCount` does nothing here

`config.threadPoolCount` and `config.workerCount` belong to the `httpz`
frontend, which is no longer the default. The shipped image runs the
`std.Io`-based frontend, where the runtime gives each connection a task and
neither value is read. If you carry a `threadPoolCount` from an older chart,
it is inert; drop it. `maxConnections` is the concurrency dial now.

If a pod is OOMKilled with nothing in its logs, look at peak
`edge_connections_active` first. The kernel gives the process no chance to log.

## Notes

- Each upstream attempt has a fixed 30s deadline; a request that exceeds it
  returns 504. Inbound requests and idle keep-alives also time out after 30s.
  None of these are configurable.
- A connection owns its whole upstream exchange, so sustained throughput is
  about `concurrent connections / upstream_round_trip`. The Datadog intake
  answers in about 14ms on a warm connection, so 64 senders in flight sustain
  roughly 4.5k requests/sec per pod. `maxConnections` is the ceiling on that;
  raise it and `resources.limits.memory` together — see Sizing.
- Log intake routes replay once on a fresh upstream connection when the first
  attempt fails before a response, if the body was buffered. A streamed
  passthrough body has nothing to replay. A replay can duplicate log lines if
  the upstream accepted the first attempt but its acknowledgement was lost.
- `workspace_id` is not required in `config.json`.
- If `tero.url` is set, chart requires either `tero.apiKey` or
  `tero.existingSecret.name`.
