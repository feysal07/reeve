# Reeve on one machine

The collector, Prometheus and Grafana, in one command.

```bash
cd deploy/compose
docker compose up -d
```

Then point an agent at it:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
```

and open <http://127.0.0.1:3000>.

The [Helm chart](../helm/reeve-collector) covers Kubernetes. This covers the case that
comes first: one person, one machine, finding out whether any of this is worth
deploying. Nothing here is meant for production.

## What is running

| | port | what it is |
|---|---|---|
| collector | 4318 | OTLP over HTTP, both encodings. This is what agents write to |
| prometheus | 9091 | scrapes the collector's own metrics, on a different port from 4318 |
| grafana | 3000 | one provisioned dashboard, no login |

The event store lives in a named volume, so `docker compose down` keeps it and
`docker compose down -v` does not.

## Everything is bound to 127.0.0.1, on purpose

**The collector has no authentication, and cannot have any.** It accepts OTLP from
agents that have no way to present a credential it would recognise. That is why the
Helm chart will not render an ingress until you assert that something in front of it
is doing authentication. There is nothing in front of it here, so nothing outside this
machine can reach it.

Changing `127.0.0.1:` to `0.0.0.0:` publishes an unauthenticated write endpoint to
your network. Anyone who can reach it can put anything they like into your cost
figures.

Grafana runs with anonymous admin access for the same reason: it is reachable only
from this machine, and the metrics it reads contain no identity. If you publish port
3000, put the login back.

## What is in the metrics, and what is not

The dashboard shows usage and cost with **no identity in it**: no emails, no sessions,
no repository names. Those go to the event store, which has different access control
and different retention, and `reeve report` reads them.

You can check this rather than taking it on trust. Send an event carrying an email,
then look for it:

```bash
curl -s 'http://127.0.0.1:9091/api/v1/series?match[]={__name__=~"reeve_.*"}' | grep example.com
```

Prompt and response content is never stored at all, whatever an agent is configured to
send.

## Two things on the dashboard worth understanding

**Computed cost and vendor-reported cost are separate series. Do not add them.** They
are two measurements of the same spending, kept apart so a disagreement between them
is visible instead of being averaged into one number nobody can check.

**Unpriced requests are counted separately.** A request whose model is not in your
price table carries tokens and cost real money, and none of it is in the cost figure.
Counting it as zero would understate the total while the dashboard looked complete.
Add the model to `config/prices.yaml` and restart the collector.

## Configuration

Everything the collector reads is in `config/`, mounted read-only:

- `teams.yaml` — who belongs to which team. Attribution comes from here rather than
  from an attribute the agent asserts about itself, because an agent runs on a
  developer's machine and anything it says about itself is a claim.
- `prices.yaml` — your rates, not list prices.
- `prometheus.yml` — one scrape target.
- `grafana/` — the datasource and dashboard, provisioned so a fresh start gives the
  same thing every time.

Edit and `docker compose restart collector`.

## The init container

Docker creates named volumes owned by root, and the collector image runs as `nonroot`,
because a process accepting network input has no business being root. The one-shot
`init` service chowns the volume before the collector starts. Without it the collector
cannot open its own event store and restarts for ever — which is exactly how this file
behaved the first time it was run, before it was run.

## Pinning

Image tags here are pinned to exact versions, including the Reeve image. Change
`ghcr.io/feysal07/reeve:0.3.0` when you upgrade, so that what you are running is a
decision rather than whatever `latest` resolved to this morning.
