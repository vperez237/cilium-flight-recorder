{{/*
Expand the name of the chart.
*/}}
{{- define "flight-recorder.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "flight-recorder.fullname" -}}
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
Chart name and version as used by the chart label.
*/}}
{{- define "flight-recorder.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "flight-recorder.labels" -}}
helm.sh/chart: {{ include "flight-recorder.chart" . }}
{{ include "flight-recorder.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "flight-recorder.selectorLabels" -}}
app.kubernetes.io/name: {{ include "flight-recorder.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "flight-recorder.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "flight-recorder.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image reference. When image.tag is empty, defaults to "v<AppVersion>" —
the release workflow publishes that tag alongside the bare semver form
and "latest", and the v-prefixed form matches the cloud-native convention
most users will expect (Cilium, Prometheus, etc. all tag this way).
An explicit image.tag value is used verbatim, no prefix inserted.
*/}}
{{- define "flight-recorder.image" -}}
{{- $tag := .Values.image.tag -}}
{{- if not $tag -}}
  {{- $tag = printf "v%s" .Chart.AppVersion -}}
{{- end -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end }}
