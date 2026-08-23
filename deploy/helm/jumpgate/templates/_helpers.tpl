{{/*
Expand the name of the chart.
*/}}
{{- define "jumpgate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this
(by the DNS naming spec).
*/}}
{{- define "jumpgate.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "jumpgate.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "jumpgate.labels" -}}
helm.sh/chart: {{ include "jumpgate.chart" . }}
{{ include "jumpgate.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels
*/}}
{{- define "jumpgate.selectorLabels" -}}
app.kubernetes.io/name: {{ include "jumpgate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Secret name resolvers: use the operator-provided existingSecret when set,
otherwise fall back to a chart-managed Secret name.
*/}}
{{- define "jumpgate.masterKeySecret" -}}
{{- if .Values.masterKey.existingSecret }}{{ .Values.masterKey.existingSecret }}{{- else }}{{ include "jumpgate.fullname" . }}-master-key{{- end }}
{{- end -}}
{{- define "jumpgate.meshCASecret" -}}
{{- if .Values.mesh.ca.existingSecret }}{{ .Values.mesh.ca.existingSecret }}{{- else }}{{ include "jumpgate.fullname" . }}-mesh-ca{{- end }}
{{- end -}}
{{- define "jumpgate.adminSecret" -}}
{{- if .Values.bootstrapAdmin.existingSecret }}{{ .Values.bootstrapAdmin.existingSecret }}{{- else }}{{ include "jumpgate.fullname" . }}-admin{{- end }}
{{- end -}}

{{/*
DATABASE_URL env entry, shared by the warden Deployment and the bootstrap Job so
the bundled-vs-external selection stays in one place. When postgres.enabled it
points at the bundled service; otherwise it prefers an existing Secret, then an
inline database.url, then the deprecated warden.databaseUrl, and fails clearly if
none is set (a production install MUST supply an external database).
*/}}
{{- define "jumpgate.databaseEnv" -}}
- name: DATABASE_URL
  {{- if .Values.postgres.enabled }}
  value: "postgres://{{ .Values.postgres.user }}:{{ .Values.postgres.password }}@{{ include "jumpgate.postgresHost" . }}:5432/{{ .Values.postgres.database }}?sslmode=disable"
  {{- else if .Values.database.existingSecret }}
  valueFrom:
    secretKeyRef:
      name: {{ .Values.database.existingSecret }}
      key: {{ .Values.database.existingSecretKey | default "uri" }}
  {{- else }}
  value: {{ .Values.database.url | default .Values.warden.databaseUrl | required "postgres.enabled=false requires an external database: set database.url, database.existingSecret, or (deprecated) warden.databaseUrl" | quote }}
  {{- end }}
{{- end -}}

{{/*
Service DNS hostnames referenced by component templates.
*/}}
{{- define "jumpgate.postgresHost" -}}
{{ include "jumpgate.fullname" . }}-postgres
{{- end -}}
{{- define "jumpgate.siloHost" -}}
{{ include "jumpgate.fullname" . }}-silo
{{- end -}}
{{- define "jumpgate.wardenMeshHost" -}}
{{ include "jumpgate.fullname" . }}-warden-mesh
{{- end -}}
