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
| `config.workerCount`                | int    | `null`                                         | httpz event-loop workers (null = 1; max maxConnections)       |
| `config.threadPoolCount`            | int    | `null`                                         | httpz handler threads per worker (null = 128)                 |
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

Memory is dominated by `config.threadPoolCount`, not by connection count. A
handler thread allocates its workspace on first use and then retains it for
the life of the thread, so a pod's memory tracks the number of threads that
have served a compressed body:

```
memory ~= maxConnections x 20 KiB
        + threadPoolCount x (zstdWindow + maxBodySize + 1.2 MiB)
```

A connection itself costs 20 KiB, the receive buffer — not `maxBodySize`.
`zstdWindow` is the post-decompression zstd decode window cap
(`limits.zig` `ZSTD_WINDOW_BUDGET_MAX`, bounded at 2 MiB): it tracks
`maxDecodedBytes`, not `maxBodySize`, so a decoded cap above 2 MiB does not grow
per-thread scratch. At `maxBodySize <= 2 MiB` the window equals `maxBodySize`
and the per-handler term collapses to `2 x maxBodySize + 1.2 MiB`.

Worked example at `maxBodySize` 2 MiB:

| maxConnections | threadPoolCount | approx memory | suggested request |
| -------------- | --------------- | ------------- | ----------------- |
| 256            | 8               | 46 MiB        | 64Mi              |
| 256 (default)  | 128 (default)   | 666 MiB       | 256Mi             |
| 2048           | 16              | 123 MiB       | 192Mi             |
| 4096           | 32              | 246 MiB       | 320Mi             |

At this chart's own `maxBodySize` of 1.5 MiB (and the default 16 MiB decoded
cap, which keys a 2 MiB `zstdWindow`) the default 256/128 shape works out at
about 607 MiB, which is what the shipped `resources` block is sized for.
`threadPoolCount` rose from 32 to 128 in v1.30.2, so a chart pinned to the old
resource values will not hold the current default.

To cut the footprint, lower `threadPoolCount` before you raise the memory
limit: it is the only knob that bounds retained workspace. 32 threads need
about 140 MiB, at lower throughput against a slow upstream.

If a pod is OOMKilled with nothing in its logs, suspect this first. The
kernel gives the process no chance to log.

## Notes

- Each upstream attempt has a fixed 30s deadline; a request that exceeds it
  returns 504. Inbound requests and idle keep-alives also time out after 30s.
  None of these are configurable.
- A handler thread owns its whole upstream exchange, so sustained throughput is
  about `threadPoolCount / upstream_round_trip`. The Datadog intake answers in
  about 14ms on a warm connection, so the default 128 threads sustain roughly
  4.8k requests/sec per pod. Raise `threadPoolCount` and `resources.limits.memory`
  together — see Sizing below.
- Log intake routes replay once on a fresh upstream connection when the first
  attempt fails before a response. A replay can duplicate log lines if the
  upstream accepted the first attempt but its acknowledgement was lost.
- `workspace_id` is not required in `config.json`.
- If `tero.url` is set, chart requires either `tero.apiKey` or
  `tero.existingSecret.name`.
