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

| Key                             | Type   | Default                                        | Description                                                  |
| ------------------------------- | ------ | ---------------------------------------------- | ------------------------------------------------------------ |
| `image.repository`              | string | `ghcr.io/usetero/edge`                         | Container image repository                                   |
| `image.tag`                     | string | `""`                                           | Image tag (defaults to chart `appVersion`)                   |
| `image.pullPolicy`              | string | `IfNotPresent`                                 | Image pull policy                                            |
| `container.args`                | list   | `[/etc/tero/config.json]`                      | Container args                                               |
| `container.port`                | int    | `8080`                                         | Container port                                               |
| `container.hostPort.enabled`    | bool   | `true`                                         | Enable hostPort                                              |
| `container.hostPort.port`       | int    | `8080`                                         | Host port                                                    |
| `resources.requests.cpu`        | string | `50m`                                          | CPU request                                                  |
| `resources.requests.memory`     | string | `32Mi`                                         | Memory request                                               |
| `resources.limits.cpu`          | string | `200m`                                         | CPU limit                                                    |
| `resources.limits.memory`       | string | `64Mi`                                         | Memory limit                                                 |
| `service.enabled`               | bool   | `false`                                        | Create Service                                               |
| `service.type`                  | string | `ClusterIP`                                    | Service type                                                 |
| `service.port`                  | int    | `8080`                                         | Service port                                                 |
| `daemonset.updateStrategy.type` | string | `RollingUpdate`                                | DaemonSet update strategy                                    |
| `tero.url`                      | string | `""`                                           | Tero control plane base URL                                  |
| `tero.apiKey`                   | string | `""`                                           | Inline API key (creates Secret)                              |
| `tero.existingSecret.name`      | string | `""`                                           | Existing Secret name for API key                             |
| `tero.existingSecret.key`       | string | `api-key`                                      | Existing Secret key containing API key                       |
| `config.listenAddress`          | string | `0.0.0.0`                                      | Edge listen address                                          |
| `config.listenPort`             | int    | `8080`                                         | Edge listen port                                             |
| `config.upstreamUrl`            | string | `https://agent-http-intake.logs.datadoghq.com` | Default upstream URL                                         |
| `config.metricsUrl`             | string | `https://api.datadoghq.com`                    | Metrics upstream URL                                         |
| `config.logLevel`               | string | `info`                                         | Log level                                                    |
| `config.maxBodySize`            | int    | `1048576`                                      | Max request body bytes                                       |
| `config.maxUpstreamRetries`     | int    | `10`                                           | Max upstream retries                                         |
| `config.fileProvider.enabled`   | bool   | `true`                                         | Enable file policy provider                                  |
| `config.fileProvider.id`        | string | `file`                                         | File provider ID                                             |
| `config.fileProvider.path`      | string | `/etc/tero/policies.json`                      | File policy path                                             |
| `config.extraPolicyProviders`   | list   | `[]`                                           | Additional raw policy providers                              |
| `policiesJSON`                  | list   | `[]`                                           | List of raw JSON policy objects (supports multiline strings) |
| `extraEnv`                      | list   | `[]`                                           | Extra container env vars                                     |
| `extraVolumes`                  | list   | `[]`                                           | Extra pod volumes                                            |
| `extraVolumeMounts`             | list   | `[]`                                           | Extra container volume mounts                                |
| `nodeSelector`                  | object | `{}`                                           | Node selector                                                |
| `tolerations`                   | list   | `[{'operator':'Exists'}]`                      | Pod tolerations                                              |
| `affinity`                      | object | `{}`                                           | Pod affinity                                                 |
| `podAnnotations`                | object | `{}`                                           | Pod annotations                                              |
| `podLabels`                     | object | `{}`                                           | Pod labels                                                   |
| `serviceAccount.create`         | bool   | `true`                                         | Create a service account                                     |
| `serviceAccount.name`           | string | `""`                                           | Service account name override                                |
| `serviceAccount.automount`      | bool   | `true`                                         | Automount SA token                                           |

## Notes

- `workspace_id` is not required in `config.json`.
- If `tero.url` is set, chart requires either `tero.apiKey` or
  `tero.existingSecret.name`.
