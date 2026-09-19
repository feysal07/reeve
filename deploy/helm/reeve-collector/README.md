# reeve-collector

Runs `reeve collect` in Kubernetes: the endpoint AI coding agents export to, which
normalises what they send into one audit and cost record.

Everything else Reeve does runs on a developer's machine or a CI runner, where the
single binary is the point. Only the collector belongs in a cluster.

## What it deploys

A StatefulSet of exactly one pod, a Service on 4318, a second ClusterIP Service for
metrics, a PersistentVolumeClaim for the event store, and optionally ConfigMaps for
the team mapping and price table, an Ingress, a NetworkPolicy, a ServiceMonitor and a
PrometheusRule.

## Before you start

There is no published image yet. Build and push one:

```bash
docker build -t ghcr.io/feysal07/reeve:0.1.0 .
docker push ghcr.io/feysal07/reeve:0.1.0
```

Or use the floating build from `main` that CI publishes:

```bash
helm install reeve ./deploy/helm/reeve-collector \
  --set image.tag=main --set image.pullPolicy=Always
```

## Install

```bash
helm install reeve ./deploy/helm/reeve-collector \
  --namespace reeve --create-namespace \
  --set-file collector.teams.content=examples/telemetry/teams.yaml \
  --set-file collector.prices.content=examples/telemetry/prices.yaml
```

`--set-file` is the easy way to get your existing YAML into the ConfigMaps. If the
team mapping is sensitive enough that you would rather it were not a plain ConfigMap,
manage it yourself and point `collector.teams.existingConfigMap` at it.

Then check it:

```bash
helm test reeve --namespace reeve
```

The test resolves the Service, calls `/healthz` to prove something is listening and
`/stats` to prove it is the collector. It posts no event, because the store is an
audit record and a test that writes to it makes that record slightly untrue every
time it runs.

## Seven things the chart refuses to do

Each is a deployment that would come up green and be wrong. Helm fails at render, so
nothing is applied and nothing has to be undone.

**`replicaCount` above 1.** The collector writes one append-only file. A second
replica would open a second file, the Service would spread agents across both, and
every report would be computed from whichever half it happened to read. No error,
just wrong totals. If you need more than one pod's capacity, the collector has to
change; raising the number will not do it.

**An Ingress without TLS.** Events carry developer identities, repository names and
model spend.

**An Ingress without `ingress.authenticatedByProxy=true`.** The collector has no
authentication of its own. Anything that can POST to it can write events under any
identity and any team, and a forged event is indistinguishable from a real one in
both the audit trail and the cost report. Put mutual TLS, an OAuth2 proxy, an ingress
auth annotation or a service mesh in front of it, then set the flag to record that
you did. The chart cannot verify the claim. It exists so that exposing an
unauthenticated write endpoint is a decision someone took rather than a default they
inherited.

**A NetworkPolicy alongside an Ingress with no permitted sources.** The policy would
deny the ingress controller too. The endpoint would resolve and then time out, agents
would stop reporting, and an agent that cannot export mostly carries on working — so
the first sign would be a gap in the audit trail that nobody notices until they go
looking for it.

**A NetworkPolicy alongside a ServiceMonitor with nothing allowed to scrape.** Same
shape, one layer up: Prometheus would be denied, every scrape would fail, and the
monitoring that exists to tell you the collector has gone quiet would itself be the
thing that was quiet.

**A ServiceMonitor with `collector.metrics.enabled=false`.** It would select nothing,
and an operator reading the cluster would see scrape configuration in place and
conclude the collector was being watched.

**A PrometheusRule with `collector.metrics.enabled=false`.** Every alert would
evaluate against a metric that is never published. Most would stay silent for ever,
which reads as healthy.

## Reaching it from a developer machine

Agents run outside the cluster, so a ClusterIP Service reaches nothing that matters.
Either enable the Ingress, with the conditions above, or forward the port to try it:

```bash
kubectl --namespace reeve port-forward svc/reeve-reeve-collector 4318:4318
```

Then point an agent at it, which `reeve policy compile` will write into managed
settings for you:

```
OTEL_EXPORTER_OTLP_ENDPOINT=http://collector.internal:4318
```

Both OTLP/HTTP encodings are accepted, protobuf and JSON, chosen by Content-Type.
gRPC is not supported: an exporter set to `grpc` fails to connect rather than
appearing to work.

## Metrics

The collector reports on itself in Prometheus format, on a listener of its own and a
Service of its own — never on the port agents export to. That port is usually
reachable from every developer machine, and the metrics there would say which agents
are in use, how busy the organisation is and what it is spending. Keeping them apart
also means turning the agent-facing Service into a LoadBalancer cannot publish them
by accident.

```bash
helm upgrade reeve ./deploy/helm/reeve-collector --reuse-values   --set serviceMonitor.enabled=true   --set prometheusRule.enabled=true
```

Both need the Prometheus operator's CRDs, which is why both are off by default.
Without the operator, scrape `<release>-reeve-collector-metrics:9464/metrics`.

What is published: batches received and rejected by signal, events written by agent
and kind, tokens and computed cost by agent, requests whose model was not in the
price table, store write failures, and the store's size and last-write time.

**No label carries an email, a subject, a session or a repository.** A metrics
endpoint is scraped by a system with different retention and far wider read access
than the event store; copying identities into it would turn the monitoring stack into
a second, unmanaged record of who did what. Labels are also bounded on purpose: the
agent name arrives in an attribute the sender controls, so anything unrecognised is
counted as `other` rather than minting a time series per request.

The two expressions worth alerting on:

```
time() - reeve_store_modified_timestamp_seconds   # the trail has gone quiet
reeve_store_size_bytes                            # the volume is filling
```

The first is the one a person cannot notice. An agent that cannot export mostly
carries on working, so a collector that has stopped receiving looks exactly like an
organisation with nothing to report. `prometheusRule.enabled=true` ships that alert
and five others.

## Storage

Nothing prunes the event file. It only grows, at roughly 300 bytes per event.

`reeve_store_size_bytes` reports the file. The volume's capacity is not something the
collector can see, so the headroom alert in this chart uses the kubelet's own metric:

```
kubelet_volume_stats_available_bytes{persistentvolumeclaim="store-reeve-reeve-collector-0"}
```

A full volume stops the collector accepting events, and agents that cannot export
mostly carry on working, so the audit trail goes quiet without anything appearing to
break.

To archive and reclaim, stop the writer first. The collector holds the file open, so
renaming it while the pod runs leaves new events going into the renamed file:

```bash
# 1. Stop it. The file is closed cleanly on SIGTERM.
kubectl --namespace reeve scale statefulset/reeve-reeve-collector --replicas=0

# 2. Mount the claim somewhere you can read it, copy the file out, then remove it.
#    (Any pod that mounts store-reeve-reeve-collector-0 will do.)

# 3. Start it again. The next helm upgrade would also restore the replica.
kubectl --namespace reeve scale statefulset/reeve-reeve-collector --replicas=1
```

Events produced during that window are lost. Agents retry for a while, not forever,
so do it when little is running.

`reeve report` reads the whole store into memory. Inside the pod that is bounded by
the memory limit, which is 256Mi by default and will not survive a store of any size.
For a large one, copy it out and run the report where there is room.

## Upgrade and uninstall

`helm uninstall` leaves the PersistentVolumeClaim behind. StatefulSet claims are not
garbage collected, and that is the behaviour you want here: deleting an audit trail
should be a separate, deliberate act.

Editing `collector.teams.content` or `collector.prices.content` rolls the pod, via a
checksum annotation. Without that a `helm upgrade` would report success while the
running collector carried on attributing events the old way.

## What is not here

- **No authentication.** See above. The right answer is an authenticating proxy that
  derives identity from a token rather than from what the agent asserts.
- **No metrics about what the guard refused.** Decisions are written to the guard's
  log on each developer machine, not sent to the collector, so they reach the report
  and not this endpoint.
- **No horizontal scale.** One writer, by construction.
- **No retention policy.** The store grows until you archive it.
