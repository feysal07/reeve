{{/*
Expand the name of the chart.
*/}}
{{- define "reeve-collector.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
A fully qualified app name, kept under the 63 character label limit.
*/}}
{{- define "reeve-collector.fullname" -}}
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

{{- define "reeve-collector.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "reeve-collector.labels" -}}
helm.sh/chart: {{ include "reeve-collector.chart" . }}
{{ include "reeve-collector.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: collector
app.kubernetes.io/part-of: reeve
{{- end }}

{{- define "reeve-collector.selectorLabels" -}}
app.kubernetes.io/name: {{ include "reeve-collector.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "reeve-collector.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "reeve-collector.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
The resolved image reference. Printed in NOTES as well as used in the pod, so
that an install pointing at a tag nobody has pushed is visible before the pull
fails rather than after.
*/}}
{{- define "reeve-collector.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}

{{/*
Where the event store lives inside the container.
*/}}
{{- define "reeve-collector.storePath" -}}
{{- printf "%s/%s" (trimSuffix "/" .Values.persistence.mountPath) .Values.persistence.storeFile }}
{{- end }}

{{- define "reeve-collector.teamsConfigMap" -}}
{{- if .Values.collector.teams.existingConfigMap }}
{{- .Values.collector.teams.existingConfigMap }}
{{- else if .Values.collector.teams.content }}
{{- printf "%s-teams" (include "reeve-collector.fullname" .) }}
{{- end }}
{{- end }}

{{- define "reeve-collector.pricesConfigMap" -}}
{{- if .Values.collector.prices.existingConfigMap }}
{{- .Values.collector.prices.existingConfigMap }}
{{- else if .Values.collector.prices.content }}
{{- printf "%s-prices" (include "reeve-collector.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Refuse to render a deployment that would silently produce a wrong answer, or
quietly expose a write endpoint. These run before anything is applied, so the
failure costs nothing.

Called once from the StatefulSet, which every install renders.
*/}}
{{- define "reeve-collector.validate" -}}
{{- if gt (int .Values.replicaCount) 1 }}
{{- fail (printf `reeve-collector: replicaCount is %d.

The collector writes one append-only event file. A second replica would open a
second file, the Service would spread agents across both, and every report would
be computed from whichever half it happened to read. No error would appear; the
totals would just be wrong.

If you need capacity beyond one pod, that is a real request and the collector has
to change to support it. Raising this number will not do it.` (int .Values.replicaCount)) }}
{{- end }}
{{- if and .Values.networkPolicy.enabled .Values.ingress.enabled (not .Values.networkPolicy.ingressFrom) }}
{{- fail `reeve-collector: networkPolicy.enabled and ingress.enabled are both true,
but networkPolicy.ingressFrom is empty.

The policy would deny every source, including the ingress controller, so the
Ingress would resolve and then time out. Agents would stop reporting, and an agent
that cannot export mostly carries on working, so the first sign would be a gap in
the audit trail that nobody notices until they go looking.

Name the ingress controller's namespace, for example:

  networkPolicy:
    ingressFrom:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: ingress-nginx` }}
{{- end }}
{{- if .Values.ingress.enabled }}
{{- if not .Values.ingress.tls }}
{{- fail `reeve-collector: ingress.enabled is true but ingress.tls is empty.

Events carry developer identities, repository names and model spend. Over plain
HTTP those cross the network in the clear, and anything on the path can inject
events that are indistinguishable from real ones.

Set ingress.tls, or terminate TLS in front of the cluster and reach the collector
by some other route.` }}
{{- end }}
{{- if not .Values.ingress.authenticatedByProxy }}
{{- fail `reeve-collector: ingress.enabled is true but ingress.authenticatedByProxy is false.

The collector has no authentication of its own. Anything that can POST to it can
write events under any identity and any team, and a forged event looks exactly
like a real one in the audit trail and in the cost report.

Put authentication in front of it: mutual TLS, an OAuth2 proxy, an ingress auth
annotation, or a service mesh. Then set ingress.authenticatedByProxy=true to
record that you did.

The chart cannot verify this. The flag exists so that exposing an unauthenticated
write endpoint is a decision someone took, rather than a default they inherited.` }}
{{- end }}
{{- end }}
{{- end }}
