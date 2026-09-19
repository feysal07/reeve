# Telemetry and reporting

`reeve collect` receives what agents report. `reeve report` answers the questions that
follow: what is this costing, per team and per repository, across every agent at once,
and what did the policy actually stop.

## Which agents this covers

`reeve scan`, `reeve guard` and `reeve policy compile` cover Claude Code, GitHub
Copilot CLI, Codex CLI, Gemini CLI and Cursor.

The collector accepts telemetry from one more, OpenCode, and attributes it by name
rather than lumping it in with everything unrecognised. There is no adapter for it, so
a report can show an OpenCode row for an agent `reeve scan` will never find and
`reeve guard` will refuse to answer for. That is deliberate: writing an adapter from
documentation nobody here has checked against a real installation would be exactly the
kind of confident wrongness this tool is built to catch.

Anything else that reaches the collector is labelled `other` in the metrics, and
`unidentified` when the payload said nothing about who sent it. Those are different
problems and are kept apart.

## Why not just point an off-the-shelf collector at the agents

You can, and you will get four incompatible datasets.

Every agent names the same measurement differently. Claude Code emits
`claude_code.token.usage` with a `type` attribute; Copilot emits
`gen_ai.client.token.usage` with `gen_ai.token.type`; Gemini emits
`gemini_cli.token.usage`; Codex emits its own event stream rather than metrics at all.
Summing them requires knowing all four. Cursor emits nothing locally: its usage lives
in Cursor's own service and is read back from their API.

They also disagree about cost. Most report none at all. The one that does calls it an
estimate at published list price, which is wrong for any organisation with negotiated
rates. So Reeve computes cost centrally from token counts, using a price
table you supply, and keeps the vendor's own figure in a separate column so the two can
be compared rather than conflated.

And none of them can report a refusal. An agent's telemetry describes what it did. An
action the guard stopped never happened as far as the agent is concerned, so it appears
nowhere in vendor telemetry and nowhere in any vendor's audit API. The guard's decision
log is the only record, and joining the two is the only way to get a trail covering
both what was done and what was prevented.

## Running the collector

```
reeve collect \
  --addr 0.0.0.0:4318 \
  --store /var/lib/reeve/events.jsonl \
  --teams /etc/reeve/teams.yaml \
  --prices /etc/reeve/prices.yaml
```

Agents need no plugin. Each already knows how to export OpenTelemetry, and
`reeve policy compile` writes the destination into their managed settings for you.

In Kubernetes, use the chart at
[deploy/helm/reeve-collector](../deploy/helm/reeve-collector), which wires the same
flags and adds the things a cluster needs: a persistent volume for the store, the
team mapping and price table as ConfigMaps that roll the pod when they change, and a
refusal to deploy shapes that would silently split or forge the record.

Endpoints: `/v1/metrics`, `/v1/logs`, `/v1/traces`, plus `/healthz` and `/stats`.
Traces are accepted and discarded, because an agent whose trace export fails may log
errors or back off its other exports, and traces add little the event stream does not
already carry.

**Encoding.** Both OTLP over HTTP encodings are read, protobuf and JSON, chosen by the
request's Content-Type as the specification requires. Protobuf is what most exporters
send by default, so nothing needs configuring beyond the endpoint:

```
OTEL_EXPORTER_OTLP_ENDPOINT=http://collector.internal:4318
```

gRPC is not supported. An exporter set to `grpc` will fail to connect rather than
appear to work.

The protobuf decoder is written by hand rather than built on the generated
OpenTelemetry packages, which would add five megabytes to a binary meant to be dropped
on every developer machine and CI runner. The risk that carries is handled by testing
rather than by the dependency: the official packages are imported by the tests, used to
marshal real OTLP messages, and the decoder's output is compared against the JSON
path's. Test-only imports are not linked into the binary, so the decoder is checked
against the canonical implementation while the shipped artifact stays small.

## Watching the collector itself

`--metrics-addr` serves Prometheus metrics about the collector: batches received and
rejected, events written by agent and kind, tokens and computed cost by agent,
requests it could not price, store write failures, and the store's size and last-write
time.

```
reeve collect --store ./events.jsonl --metrics-addr 127.0.0.1:9464
```

They are on a listener of their own, never on the port agents export to. That port is
the one reachable from developer machines, and metrics served there would tell anyone
who asked which agents are in use and what they cost. If the address cannot be bound
the collector refuses to start rather than running without it, because a collector
that is up but unscrapable looks healthy from every direction except the one that
matters.

The expression worth alerting on is the least obvious:

```
time() - reeve_store_modified_timestamp_seconds
```

An agent that cannot export mostly carries on working. Nothing errors, no request
fails, and the developer notices nothing. A collector that has stopped receiving
therefore looks exactly like an organisation with nothing to report, and that
distance from the last write is the only thing that tells them apart.

**No label carries an email, a subject, a session or a repository.** The event store is
access controlled and retained as an audit record; a metrics endpoint is scraped by a
system with different retention and much wider read access, and copying identities
into it would create a second, unmanaged record of who did what. A test fails if any
of them ever appear.

Label values are also bounded deliberately. The agent name arrives in a resource
attribute the sender sets, and `reeve.agent` is passed through verbatim so a new
vendor can be collected before an adapter exists for it. That is right for the store
and wrong for a metric, where every distinct value is a series the monitoring system
keeps: anything unrecognised is counted as `other` rather than minting one per
request. Unpriced requests are counted per agent and not per model for the same
reason; `reeve report` names the models.

The exposition format is written by hand rather than taken from the Prometheus client
library, for the same reason as the protobuf decoder, and checked the same way: the
canonical parser is imported by the tests and used to read the output back. Neither
library is linked into the binary.

## Attribution is resolved, not trusted

An agent runs on a developer's machine, so every attribute it sends is asserted by that
machine. A developer who wanted their spend attributed to another team could simply say
so in an environment variable.

Team is therefore resolved by the collector from a mapping you control
([examples/telemetry/teams.yaml](../examples/telemetry/teams.yaml)), never from a
client-supplied attribute. Identities are marked `asserted` in the stored event, so a
consumer knows how much weight to give them. Spend that matches nothing lands in an
`unattributed` bucket rather than disappearing.

For attribution that is proven rather than asserted, put an authenticating proxy in
front of the collector and derive identity from the token. That is the right answer and
is not built yet.

## Pricing

Supply your own table ([examples/telemetry/prices.yaml](../examples/telemetry/prices.yaml)).
The built-in one is at published list rates, is incomplete, and will go out of date; the
collector warns when it is being used.

A model with no entry is reported as **unpriced** rather than costed at zero. Zero is
indistinguishable from free, and a report that quietly treats an unpriced model as
costing nothing understates the total while looking complete. The report says how many
requests it could not price.

`multiplier` scales every computed cost, for an organisation that recharges at a rate
other than the one it pays.

## What is stored

One JSON object per line, append-only. A line-delimited file survives a crash mid-write
without corrupting what came before, can be read by anything, and can be shipped to a
real store later without the format changing.

**Prompt and response content is never stored**, even when an agent is configured to
send it. A store that sometimes contains secrets has to be treated as though it always
does, which would change how it must be encrypted, retained and access-controlled. The
decoder drops content regardless of what arrives, and a test fails if that ever stops
being true.

What is kept: who, when, which agent, which model, token counts, computed cost,
repository, tool name, duration, and the guard's decision with its rule id.

## Reporting

```
reeve report --store /var/lib/reeve/events.jsonl \
             --decisions /var/log/reeve/decisions.jsonl \
             --since 168h
```

Gives cost and usage by team, agent, user, repository and model, plus which policy
rules fired and how often they blocked something. `--json` emits the same aggregation
for a dashboard to consume.

A gap between the computed cost and the vendor's own figure is shown rather than
reconciled. It usually means a model is unpriced locally, or the agent is reporting
list price where you pay something else. Both are worth knowing.

Note that a dry-run deny counts as a decision but not as a block, because the action
went ahead. Counting it as blocked would overstate what the deployment prevented.

## Deploying

Run one collector per environment, behind your own ingress. Nothing here authenticates
the caller, so it must not be exposed to a network you do not control. Put it behind a
proxy that terminates TLS and checks a token.

Retention is your responsibility: rotate the store file the way you rotate any other
log. Events carry who did what and when, which is personal data even without prompt
content, so the store is created mode 0600 and should be treated accordingly.
