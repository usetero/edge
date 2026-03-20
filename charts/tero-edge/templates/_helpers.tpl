{{/*
Expand the name of the chart.
*/}}
{{- define "tero-edge.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "tero-edge.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "tero-edge.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "tero-edge.labels" -}}
helm.sh/chart: {{ include "tero-edge.chart" . }}
{{ include "tero-edge.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "tero-edge.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tero-edge.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "tero-edge.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "tero-edge.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Resolve API key secret name.
*/}}
{{- define "tero-edge.apiKeySecretName" -}}
{{- if .Values.tero.existingSecret.name -}}
{{- .Values.tero.existingSecret.name -}}
{{- else -}}
{{- printf "%s-api-key" (include "tero-edge.fullname" .) -}}
{{- end -}}
{{- end }}

{{/*
Resolve API key secret key.
*/}}
{{- define "tero-edge.apiKeySecretKey" -}}
{{- .Values.tero.existingSecret.key | default "api-key" -}}
{{- end }}

{{/*
Validate top-level Tero auth config.
*/}}
{{- define "tero-edge.validateTeroAuth" -}}
{{- $uses_http := ne .Values.tero.url "" -}}
{{- $has_inline := ne .Values.tero.apiKey "" -}}
{{- $has_secret := ne .Values.tero.existingSecret.name "" -}}
{{- if and $uses_http (not (or $has_inline $has_secret)) -}}
{{- fail "tero.url is set but no auth configured. Set tero.apiKey or tero.existingSecret.name." -}}
{{- end -}}
{{- if and $has_inline $has_secret -}}
{{- fail "Set either tero.apiKey or tero.existingSecret.name, not both." -}}
{{- end -}}
{{- end }}
