# Telemetry and reporting

`reeve collect` receives what agents report. `reeve report` answers the questions that
follow: what is this costing, per team and per repository, across every agent at once,
and what did the policy actually stop.

## Cost is not the same as money

Reeve computes cost from tokens and your price table. That figure is **equivalent
cost**: what the usage would cost at those rates. It is a real measure of consumption,
comparable across vendors, and the right basis for internal recharge — which is what
`multiplier` is for.

It is **not money that left the organisation**, and for most people deploying this it
is nowhere near it. A Claude Teams seat, a Copilot seat and a Cursor seat are all paid
for in advance and include an allowance. Tokens inside that allowance are already
bought; their marginal cost is nothing. A report saying "$340 this week" to such an
organisation is quoting a number that looks like money and is not.

So declare how you actually pay, in the `billing` section of the price table. An
organisation of any size mixes tiers, so it is a list of plans rather than one seat
count, and each tier lists what it includes:

```yaml
billing:
  claude-code:
    model: subscription
    overage: credits          # credits | throttled | blocked
    plans:
      teams-standard:
        seats: 24
        limits:
          - {unit: tokens, included: 20000000,  per: seat, period: "168h", label: weekly tokens}
      teams-premium:
        seats: 1
        limits:
          - {unit: tokens, included: 100000000, per: seat, period: "168h", label: weekly tokens}
          - {unit: tokens, included: 2000000,   per: seat, period: "5h",   label: session tokens}

  copilot-cli:                # metered in requests, not tokens
    model: subscription
    overage: blocked
    plans:
      business:
        seats: 25
        limits:
          - {unit: requests, included: 300, per: seat, period: "720h", label: monthly premium requests}

  codex-cli:
    model: metered
```

Four things that single number could not say, and each of them changes the answer:

| field | why it is not optional |
|---|---|
| `plans` | Tiers are held side by side. Averaging them produces an allowance nobody has. |
| `unit` | Copilot meters premium requests, Anthropic meters tokens. Comparing one against the other is wrong by orders of magnitude, not by a rounding error. |
| `per` | `seat` or `organisation`. A per-seat limit reported only as a fleet total is a green light with somebody already over the line behind it. |
| `period` | Several windows run at once and they run out at different times. Declare the short one and the long one; the short one is what a developer actually hits. |

`overage` is optional and says what running out costs: `credits` is a bill,
`throttled` is lost time, `blocked` is an outage. "110% of allowance" is not
actionable without it.

`reeve report --prices` then separates money from consumption:

```
  equivalent   : $140.42 at your rates, from tokens
  money spent  : $0.00

Included allowance

  claude-code, session tokens
    organisation : 2.1M of 2.0M used (104%) across 1 seat(s)
    scope        : only 1 of the 25 seats held are on a tier declaring this limit, but
                   consumption from all of them is counted against it, because the
                   telemetry does not say who is on which tier. Read this row as an
                   upper bound.
    pace         : 1.04x the rate that would just use it up, ON COURSE TO RUN OUT
    over a seat  : 1 person(s) past the 2.0M a single seat includes
                   heavy@example.com                  2.1M (104%)
    past it      : draws on credits, so past this point consumption does cost money

  claude-code, weekly tokens
    organisation : 323.3M of 580.0M used (56%) across 25 seat(s)
    over a seat  : 1 person(s) past the 100.0M a single seat includes
                   heavy@example.com                  288.1M (288%)
```

### What each vendor calls a person

Every agent invents its own identifier. Anthropic reports an account UUID, Copilot a
GitHub login, Cursor its own user id, and none of them is the subject your identity
provider issues. A budget written per person compares the identity the guard resolved
against subjects recorded by four different vendors, and matches none of them.

It fails quietly: the window totals zero, and a budget compared against zero permits.
Measured, not supposed — nine million tokens against a thousand-token budget, allowed,
with no reason given. So map them, in `teams.yaml`:

```yaml
aliases:
  "acct_01HXY9Z-anthropic-account-uuid": "8f14e45f-ea0c-4f2b-9a1d-1c2d3e4f5a6b"
  "octocat": "8f14e45f-ea0c-4f2b-9a1d-1c2d3e4f5a6b"
  "dev@example.com": "8f14e45f-ea0c-4f2b-9a1d-1c2d3e4f5a6b"
```

Applied where the event is recorded, so the report, the metrics and a person-scoped
budget in the guard all agree by construction. An alias that points at another alias is
refused when the file is read, because resolving one hop into a chain gives an answer
that depends on how many times the mapping ran. Addresses are matched in lower case, and
a key written with capitals is refused for the same reason: an alias that never matches
looks exactly like one nobody needed.

> **This makes a per-person budget work. It does not make it evidence.**
>
> The alias key is matched against `user.id` and `user.email`, which the agent puts in
> its own export, from the machine being governed. That is why every identity on a
> stored event is marked as asserted. Setting `user.id` to a colleague's subject already
> filed spend under that colleague before aliases existed and still does; an alias adds
> a more guessable handle for the same thing rather than a new weakness.
>
> A person-scoped budget is therefore worth whatever your collector's ingest controls
> are worth, and the collector has none — it accepts what it is sent, on a port bound to
> localhost. Treat these budgets as a guardrail against a runaway, which is what they
> are good at, and not as an audit trail for a chargeback dispute. The guard's decision
> log is the half nobody can forge from the agent side.

**Upgrading:** if you already key `subjects:` on a vendor's identifier rather than on
your identity provider's, adding an `aliases:` section will rewrite the subject before
that lookup runs and the old entry will stop matching. Move those entries to `aliases:`
and key `subjects:` on the canonical subject.

**Read the second row before the first.** The organisation is at 56% of its weekly
allowance — comfortable, and the only figure a fleet total would have given you. One
person is at 288% of the most generous seat the organisation holds. A per-seat
allowance is a statement about a person, and reporting it only in aggregate hides
exactly the case worth knowing about.

The allowance lines are the ones a seat-based customer can act on. Their outlay was
fixed when they bought the seats; what varies is whether the included consumption
lasts the period. A dollar total never told them that.

**An agent you do not declare is reported as not known, never as zero and never as
metered.** Assuming metered overstates money for most organisations; assuming
subscription understates it to nothing for the rest.

**Budgets should follow the same logic.** A `spend` rule in dollars governs money, which
under a subscription is fixed — so `reeve policy check` warns when it sees one. Use a
token budget for the quantity that actually runs out:

```yaml
match:
  tokens: {within: 168h, moreThan: 5000000, scope: machine}
```

**What Reeve cannot know.** The telemetry reports consumption; it never says "this
request drew on credits rather than the allowance", and it never says which tier the
person at the keyboard is on. So an individual is reported as over only once they have
passed even the largest seat you declare — the only claim the evidence supports — and
your credit balance is left to the vendor's own console. Reading that would mean an
outbound call to the vendor, which nothing here does.

## Gating on the report

`reeve scan` and `reeve posture` both fail a build on what they find. `reeve report`
does too:

```bash
reeve report --store ./events.jsonl --prices ./prices.yaml --fail-on allowance.over-seat
```

The conditions are named rather than graded, because they are different questions
rather than different severities:

| condition | what it means |
|---|---|
| `allowance.over-seat` | somebody has consumed more than a single seat includes, whatever the organisation total says |
| `allowance.over-total` | the organisation has used its whole allowance for a window |
| `allowance.pace` | on course to run out before the period resets — the one that fires while there is still time to act |
| `billing.undeclared` | priced usage belonging to an agent whose arrangement nobody declared |
| `billing.silent` | an allowance was declared and **nothing has ever been measured against it** |
| `prices.unpriced` | requests on a model with no entry in the price table |
| `identity.unmatched` | consumption recorded under subjects your team map does not name, even after aliases, which a per-person budget counts none of |
| `identity.unattributed` | consumption from identities your team map matched nothing about, counted under its default team, which a team budget counts none of |

`--fail-on any` selects all of them. An unrecognised name is an error rather than a
no-op: a gate configured with a typo that silently passes everything is worse than no
gate, because somebody has been told the build is checking.

`billing.silent` is the one worth wiring up first, and it ships wired: Copilot exports
no per-token telemetry, so declare an allowance for it, never finish wiring the export,
and every report and every dashboard says nought per cent for ever — which is exactly
what an organisation comfortably inside its limits looks like. See
[the alerts](#the-alerts-are-shipped-not-described) for the rule that catches it.

`identity.unmatched` is the detection half of the alias map. A budget compared against
events it cannot attribute totals zero, and zero permits: measured, a per-person budget
allowed somebody nine million tokens over a thousand-token limit because the events were
recorded under an Anthropic account UUID and the guard asked about an SSO subject. The
collector now records, per event, whether the subject is one your team map names — in
`subjects`, or as the target of an alias — and whether the map matched the identity at
all. The report counts both, with the tokens behind them and the heaviest few by name, so
the alias to write is not a search:

```
identity.unmatched: 1 identity whose subject the team map does not name, even after
aliases (9.0M tokens), so a per-person budget keyed on your subjects counts none of it.
Heaviest: dev@example.com. Add an alias for them
```

They are two conditions because they answer to two kinds of budget. Gate on
`identity.unmatched` if any policy has a per-person rule; an organisation without one has
no use for it, since every subject it never named will appear there. Gate on
`identity.unattributed` if any policy has a per-team rule. The subject half is asked of
every map, including one built from domains alone: found by review, that is exactly the
map the incident happens under, because a domain fixes the team and leaves the vendor's
id on the event.

With no team map nothing is flagged: there was nothing to have matched. **Events
collected before this release carry neither flag** and count as matched, so a window that
spans the upgrade undercounts until those events age out of it.

## The JSON report

`reeve report --json` emits a documented, versioned shape you can build on.

```json
{
  "schemaVersion": "1.0",
  "from": "2026-01-02T03:04:05Z",
  "to": "2026-01-09T03:04:05Z",
  "overall": { "sessions": 11, "requests": 22, "tokens": { "input": 41 },
               "equivalentCostUSD": 5.5, "vendorCostUSD": 10.1, "marginalUSD": 11.2 },
  "allowance": [ { "agent": "claude-code", "used": 1500, "perSeat": 1000,
                   "over": [ { "who": "dev@example.com", "used": 1400 } ] } ],
  "byTeam": [ { "key": "platform", "requests": 22 } ],
  "byAgent": [], "byUser": [], "byRepo": [], "byModel": [], "byRule": []
}
```

**Read `schemaVersion` first and refuse a version you do not know.** It is the string
`"1.0"` today. It rises whenever a field is renamed or removed; adding one does not
raise it, so treat unknown fields as ignorable rather than as an error.

Every command that emits JSON declares it the same way — `scan`, `posture`, `report`,
`doctor`, `mcp` and `audit` — always a string, never a number. It was briefly a number
here and a string elsewhere, which made a consumer type-switch on the one field whose
whole purpose is to be checked before anything else is read.

Three things worth knowing before you build on it:

- **`equivalentCostUSD` is not money.** It is tokens times the rates in your price
  table — what the usage *would* cost. `marginalUSD` is money that actually left, and
  it is summed only over events whose billing arrangement was declared; `marginalKnown`
  and `billingUndeclared` say how much of the window that covers, so a small number can
  be told from a number nobody could compute.
- **`vendorCostUSD` is the agents' own claim**, at list price. It is kept separate
  rather than merged, because summing it with a figure computed at a negotiated rate
  produces a total that is neither.
- **Durations are nanoseconds**, which is what a Go duration marshals to. The fields
  are named `elapsedNanos` and `periodNanos` so that reading them as seconds is a
  mistake you make once.
- **`allowance: null` is not `allowance: []`.** Null means no billing arrangement was
  declared, so nothing can be said about allowances at all. An empty array means one
  was declared and nothing has been measured against it — which is the `billing.silent`
  condition, and a thing worth alerting on. The `by*` groupings are the other way
  round: they are always an array, never null, because a grouping with no rows and no
  such grouping are the same statement.

Identities appear here — `byUser`, and `over[].who` — and deliberately never in the
metrics endpoint. This document is produced on demand by somebody who already has
access to the store; Prometheus is scraped by a system with much wider read access.

> **Before v0.6.0** the flag emitted Go field names — `Overall`, `ByTeam`,
> `UnpricedRequests` — mixed with the few nested types that already carried tags. That
> shape was never chosen and a rename could change it silently, so it is not carried
> forward. `CostUSD` is now `equivalentCostUSD`, matching the metric rename that made
> the same point.

## Watching it, rather than reading it

Nobody runs a report at two in the morning. `reeve collect --prices ... --metrics-addr
...` exports the same figures for Prometheus:

| series | |
|---|---|
| `reeve_allowance_included` | what the plans include for one window, in that limit's own unit |
| `reeve_allowance_used` | consumption inside the current window |
| `reeve_allowance_per_seat` | the largest single seat's included amount |
| `reeve_allowance_seats_over` | how many people are past a single seat |
| `reeve_allowance_pace` | above 1 means it will not last the period |
| `reeve_allowance_unattributed` | consumption that carried no identity |
| `reeve_allowance_read_errors_total` | times the store could not be read |

**No series here is labelled by a person.** Who is over their seat is in the event
store, which is access controlled and kept as an audit record; a metrics endpoint is
scraped by a different system with much wider read access, and copying identities into
it would quietly turn a monitoring stack into a second, unmanaged copy of who did what.
`reeve_allowance_seats_over` is a count; `reeve report` has the names.

While the store cannot be read, the allowance series are **absent rather than stale**.
Held-over figures would draw a healthy line through an outage out of numbers that were
true an hour ago, and a gap is at least visible.

### The alerts are shipped, not described

Metrics without alerts are a dashboard nobody opens, so the rules come with the
deployment rather than being left as an exercise:

- **compose** — [`deploy/compose/config/rules.yml`](../deploy/compose/config/rules.yml),
  loaded through `rule_files`. There is no Alertmanager in that stack, so a firing rule
  shows at `http://127.0.0.1:9091/alerts` and nowhere else.
- **Helm** — the same three in the chart's `PrometheusRule`, behind
  `prometheusRule.enabled`, with `allowanceSilentFor` and `paceAbove` as values.

| alert | condition | why it is an alert and not a panel |
|---|---|---|
| `ReeveAllowanceNeverMeasured` | `billing.silent` | Nought per cent for ever is the same shape as staying inside the limit |
| `ReeveAllowancePaceWillExhaust` | `allowance.pace` | Fires while there is still time to act |
| `ReeveAllowancesUnreadable` | the store cannot be read | Without it the other two are quiet for the wrong reason: the series they match on are absent |

A test asserts that every metric these name is one this build actually exports. An
alert querying a renamed series does not fail — it sits there looking like a condition
that has never been met.

`reeve_cost_usd_total` still exists so that existing dashboards keep working, but it is
now an alias for `reeve_equivalent_cost_usd_total`. The figure never was money; the
name said otherwise on every panel built from it.

## Which agents this covers

`reeve scan`, `reeve guard` and `reeve policy compile` cover Claude Code, GitHub
Copilot CLI, Codex CLI, Gemini CLI and Cursor.

The collector accepts telemetry from one more, OpenCode. There is no adapter for it, so
a report can show an OpenCode row for an agent `reeve scan` will never find and
`reeve guard` will refuse to answer for. That is deliberate: writing an adapter from
documentation nobody here has checked against a real installation would be exactly the
kind of confident wrongness this tool is built to catch.

`reeve report` now says so on the row itself — **telemetry only, not governed** — for
OpenCode and for any other name the collector accepts that `reeve scan` and
`reeve guard` do not cover. Without it the row is indistinguishable from the five that
are fully covered, and the limit is only discovered when somebody goes looking for an
agent that scan cannot see.

> **Attribute an agent this build has no adapter for with `reeve.agent`.** That
> resource attribute takes precedence over everything else and is the operator's own
> channel for saying who sent a payload.
>
> Until v0.6.0 a sender that named itself in `service.name` alone and emitted the GenAI
> semantic conventions — as OpenCode does — was **counted as Copilot spend**, because an
> unprefixed `gen_ai.` metric was attributed to Copilot whatever the sender had said
> about itself. Silently, and in the direction that inflates a governed agent's figures
> with an ungoverned agent's usage. Such a payload is now left unattributed instead,
> which shows up as its own row rather than swelling somebody else's.

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

Events carry who did what and when, which is personal data even without prompt
content, so the store is created mode 0600 and should be treated accordingly.

**Retention** is `reeve collect --retain 720h`: the collector removes events older than
that, at start-up and hourly. It is done by the collector because the collector is the
store's only writer and keeps it open; anything else rewriting the file would race the
next batch, and on Windows could not replace it at all. A line the collector cannot read
is kept rather than removed, and counted, because deleting what this build cannot parse
would be retention quietly doubling as data loss. The default is to keep everything:
forgetting is something an operator chooses, not something that happens to them. A
budget whose window is longer than the retention period will total what is left, so keep
the two consistent.
