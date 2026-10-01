{{- define "reeve-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "reeve-gateway.fullname" -}}
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

{{- define "reeve-gateway.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "reeve-gateway.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: gateway
app.kubernetes.io/part-of: reeve
{{- end }}

{{- define "reeve-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "reeve-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "reeve-gateway.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "reeve-gateway.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
A field that carries a credential must be a reference, never the credential. A value
typed into values.yaml ends up in the release history, in every `helm get values`, and in
whichever repository holds the values file, where it is a secret nobody rotates because
nobody knows it is there.
*/}}
{{- define "reeve-gateway.mustBeReference" -}}
{{- $v := index . 1 -}}
{{- if and $v (not (hasPrefix "${" (toString $v))) }}
{{- fail (printf "gateway.%s holds a literal value. Put it in the Secret named by existingSecret and write ${VAR} here (or ${file:/path})." (index . 0)) }}
{{- end }}
{{- end }}

{{/*
The checks that stop a configuration which would deploy and be wrong. Called from the
Deployment so every render runs them.
*/}}
{{- define "reeve-gateway.validate" -}}
{{- $g := .Values.gateway -}}
{{- if not .Values.image.repository }}{{ fail "image.repository is required: build the image with image/Dockerfile and push it to your registry. There is no published gateway image." }}{{ end }}
{{- if not (or .Values.image.digest .Values.image.tag) }}{{ fail "image.digest or image.tag is required. Pin the gateway version your fleet runs." }}{{ end }}
{{- if eq (toString .Values.image.tag) "latest" }}{{ fail "image.tag latest is refused: every restart could run a different gateway. Pin a version, or better a digest." }}{{ end }}
{{- if not .Values.existingSecret }}{{ fail "existingSecret is required: the Secret holding the credentials gateway.yaml refers to as ${VAR}." }}{{ end }}
{{- range $s := list "listen" "oidc" "session" "store" "upstreams" }}
{{- if not (hasKey $g $s) }}{{ fail (printf "gateway.%s is required by the gateway." $s) }}{{ end }}
{{- end }}
{{- $url := toString (default "" $g.listen.public_url) }}
{{- if not (hasPrefix "https://" $url) }}{{ fail "gateway.listen.public_url must be the https:// origin developers sign in to. Plain HTTP would carry bearer tokens in the clear." }}{{ end }}
{{- if not $g.oidc.issuer }}{{ fail "gateway.oidc.issuer is required." }}{{ end }}
{{- if not $g.store.postgres_url }}{{ fail "gateway.store.postgres_url is required: the gateway keeps sign-ins and spend in Postgres." }}{{ end }}
{{- if contains "@" (toString $g.store.postgres_url) }}{{ fail "gateway.store.postgres_url carries credentials. Give the host and database here, and the password as store.password: ${DB_PASSWORD}." }}{{ end }}
{{- if not $g.upstreams }}{{ fail "gateway.upstreams needs at least one inference provider." }}{{ end }}
{{- include "reeve-gateway.mustBeReference" (list "oidc.client_secret" $g.oidc.client_secret) }}
{{- include "reeve-gateway.mustBeReference" (list "store.password" $g.store.password) }}
{{- range $j := (kindIs "slice" $g.session.jwt_secret | ternary $g.session.jwt_secret (list $g.session.jwt_secret)) }}
{{- include "reeve-gateway.mustBeReference" (list "session.jwt_secret" $j) }}
{{- end }}
{{- range $i, $u := $g.upstreams }}
{{- if $u.auth }}
{{- range $k := list "api_key" "oauth_token" "aws_secret_access_key" "aws_session_token" "aws_bearer_token" }}
{{- include "reeve-gateway.mustBeReference" (list (printf "upstreams[%d].auth.%s" $i $k) (index $u.auth $k)) }}
{{- end }}
{{- end }}
{{- end }}
{{- if not $g.listen.trusted_proxies }}{{ fail "gateway.listen.trusted_proxies is required behind an Ingress: without the ingress controller's source ranges every request appears to come from the proxy, per-IP rate limits merge into one bucket, and the audit log records the proxy's address for everyone." }}{{ end }}
{{- if .Values.ingress.enabled }}
{{- if not .Values.ingress.host }}{{ fail "ingress.host is required." }}{{ end }}
{{- if not .Values.ingress.tlsSecretName }}{{ fail "ingress.tlsSecretName is required: developers sign in here, and the gateway must be served over HTTPS." }}{{ end }}
{{- if not (eq $url (printf "https://%s" .Values.ingress.host)) }}{{ fail (printf "gateway.listen.public_url (%s) must be https://%s, the Ingress host: the gateway puts it in its discovery metadata and the IdP redirects there." $url .Values.ingress.host) }}{{ end }}
{{- range $k, $v := .Values.ingress.annotations }}
{{- if or (contains "redirect" (lower $k)) (contains "rewrite-target" (lower $k)) }}
{{- fail (printf "ingress annotation %s redirects or rewrites requests. Claude Code does not follow redirects on the device-authorization and token endpoints, so sign-in and token refresh would break. Terminate TLS at the Ingress without redirecting the gateway's paths." $k) }}
{{- end }}
{{- end }}
{{- end }}
{{- with .Values.reeveCollector.url }}
{{- if not (hasPrefix "https://" .) }}{{ fail "reeveCollector.url must be https://: the gateway refuses anything else for telemetry forwarding. Use the collector's TLS Ingress, not its in-cluster Service." }}{{ end }}
{{- end }}
{{- if and .Values.networkPolicy.enabled (not .Values.networkPolicy.ingressFrom) }}{{ fail "networkPolicy.ingressFrom is empty, which would deny the ingress controller and every developer with it. Name the controller's pods." }}{{ end }}
{{- if and .Values.networkPolicy.enabled (not .Values.networkPolicy.egressTo) }}{{ fail "networkPolicy.egressTo is empty, which would deny Postgres, the IdP and the upstream: the gateway would boot, fail OIDC discovery and never become ready. Name each destination." }}{{ end }}
{{- end }}

{{/*
The gateway.yaml, with the collector added to telemetry.forward_to when one is given.
*/}}
{{- define "reeve-gateway.config" -}}
{{- $g := deepCopy .Values.gateway -}}
{{- with .Values.reeveCollector.url }}
{{- $t := default (dict) $g.telemetry -}}
{{- $fwd := default (list) $t.forward_to -}}
{{- $entry := dict "url" . "metrics" true "logs" false "traces" false -}}
{{- if $.Values.reeveCollector.headers }}{{ $_ := set $entry "headers" $.Values.reeveCollector.headers }}{{ end -}}
{{- $_ := set $t "forward_to" (append $fwd $entry) -}}
{{- $_ := set $g "telemetry" $t -}}
{{- end -}}
{{- toYaml $g -}}
{{- end }}
