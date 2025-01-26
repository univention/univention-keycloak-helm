{{/*
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: 2024 Univention GmbH
*/}}

{{/*
If no master password is specified by the user, generate a random master password.
The generated master password has to stay consistent for a complete templating run.
*/}}

{{- if not .Values.global.secrets.seed -}}
  {{- $_ := set .Values.global.secrets "seed" (randAlphaNum 10 | sha1sum) -}}
{{- end -}}

{{/*
Default secret names.

Usage:
{{ include "nubus-common.secrets.name" (dict "suffix" "my-suffix" "context" $) }}

Params:
  - suffix - String - Required - Secret name suffix
  - context - Dict - Required. The context for the template evaluation.
*/}}
{{- define "nubus-common.secrets.name" -}}
{{- $name := printf "%s-%s" (include "common.names.fullname" .context) .suffix | trunc 63 | trimSuffix "-" }}

{{- with .existingSecret.name -}}
{{- $name = tpl . $.context -}}
{{- end -}}

{{- printf "%s" $name -}}
{{- end -}}

{{/*
Generate secret key.

Usage:
{{ include "nubus-common.secrets.key" (dict "existingSecret" .Values.path.to.the.existingSecret "key" "keyName") }}

Params:
  - existingSecret - ExistingSecret - Optional. The path to the existing secrets in the values.yaml given by the user
    to be used instead of the default one.
  - key - String - Required. Name of the key in the secret.
*/}}
{{- define "nubus-common.secrets.key" -}}
{{- $key := (required "Variable .key is required" .key) -}}

{{- if .existingSecret -}}
  {{- if .existingSecret.keyMapping -}}
    {{- $key = default $key (index .existingSecret.keyMapping $.key) -}}
  {{- end }}
{{- end -}}

{{- printf "%s" $key -}}
{{- end -}}

{{/*
Generate passwords from a common seed.

Usage:
{{ include "nubus-common.secrets.password" (dict "seed" "unique-name-as-seed" "providedValue" .Values.component.auth.password "context" $) }}

Params:
  - seed - String - Required - Custom seed that leads to a unique password. This is combined with the master password to generate a unique but reproducible password.
  - providedValue - String - Optional - User-provided value, will be returned as first priority, overriding the password generation mechanism
  - context - Dict - Required. The context for the template evaluation.
*/}}
{{- define "nubus-common.secrets.password" -}}
{{- if .providedValue }}
{{- .providedValue | quote -}}
{{- else }}
{{- $masterPassword := (required "a password seed is required" .context.Values.global.secrets.seed ) -}}
{{- (print (derivePassword 1 "long" $masterPassword "nubus" .seed ) | sha1sum) }}
{{- end }}
{{- end -}}

{{/*
Template section for a complete secret.

Usage:
{{ include "nubus-common.secrets.secretTemplate" ( dict
  "suffix" custom-name-suffix
  "passwordConfigs" ( list
    ( dict "seed" "unique-name-as-seed" "passwordConfig" .Values.component.authSection )
    ( dict "seed" "different-unique-name-as-seed" "passwordConfig" .Values.global.yourOtherSecretSection )
  )
  "context" $)
}}

Params:
  - suffix - String - Optional - Secret name suffix in cases where multiple secrets are configured.
  - passwordConfigs - List - Required - List of secret context values sections
  - context - Dict - Required. The context for the template evaluation.
*/}}
{{- define "nubus-common.secrets.secretTemplate" -}}
{{- if eq .context.Values.global.secrets.enabled true }}

{{- $any := false }}
{{- range .passwordConfigs }}
  {{- if not .passwordConfig.existingSecret.name }}
    {{- $any = true }}
  {{- end }}
{{- end }}

{{- if $any }}
---
apiVersion: v1
kind: Secret
metadata:
  name: {{ printf "%s-%s" (include "common.names.fullname" .context) .suffix | trunc 63 | trimSuffix "-" }}
  namespace: {{ include "common.names.namespace" .context | quote }}
  labels: {{- include "common.labels.standard" ( dict "customLabels" .context.Values.commonLabels "context" .context ) | nindent 4 }}
  {{- if .context.Values.commonAnnotations }}
  annotations: {{- include "common.tplvalues.render" ( dict "value" .context.Values.commonAnnotations "context" .context ) | nindent 4 }}
  {{- end }}
type: Opaque
data:
{{- range .passwordConfigs }}
  {{- if not .passwordConfig.existingSecret.name }}
  {{ required "Variable .key is required" .key }}: {{ include "nubus-common.secrets.password" ( dict "providedValue" .passwordConfig.password "seed" .seed "context" $.context ) }}
  {{- end }}
{{- end }}
...
{{- end }}
{{- end -}}
{{- end }}
