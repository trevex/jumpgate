{{/*
Fail-closed validation. Called once (see jumpgate.labels include below). Each
check fails the render with an actionable message when required security config
is missing. The demo passes only because test/env/demo-values.yaml supplies the
values — there is no demo mode in the chart.
*/}}
{{- define "jumpgate.validate" -}}
{{- /* Master key: reject the ephemeral randBytes path for a real install. */ -}}
{{- if not .Values.masterKey.existingSecret }}
{{- if not .Values.masterKey.value }}
{{- fail "masterKey is required: set masterKey.value (base64 32-byte key) or masterKey.existingSecret. A generated key rotates on every upgrade and orphans sealed vault data." }}
{{- end }}
{{- end }}
{{- /* Bootstrap admin. */ -}}
{{- if not .Values.bootstrapAdmin.existingSecret }}
{{- if or (not .Values.bootstrapAdmin.email) (not .Values.bootstrapAdmin.password) }}
{{- fail "bootstrapAdmin is required: set bootstrapAdmin.email and bootstrapAdmin.password, or bootstrapAdmin.existingSecret." }}
{{- end }}
{{- end }}
{{- /* Recording S3 credentials. */ -}}
{{- if not .Values.recording.s3.existingSecret }}
{{- if or (not .Values.recording.s3.accessKey) (not .Values.recording.s3.secretKey) }}
{{- fail "recording S3 credentials are required: set recording.s3.accessKey and recording.s3.secretKey, or recording.s3.existingSecret." }}
{{- end }}
{{- end }}
{{- end -}}
