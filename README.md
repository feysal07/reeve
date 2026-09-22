# Reeve

**A vendor-neutral, self-hosted control plane for AI coding agents.**

One command tells you which AI coding agents are on a machine, what each one is
actually allowed to do, and which of those settings a developer can change. No account,
no network calls, no agent configuration modified.

```
$ reeve scan

Agents detected (linux/amd64)

  GitHub Copilot CLI
    managed config : none
    approval mode  : manual
    bypass allowed : yes
    permission rules: 0 allow, 0 ask, 1 deny
    mcp servers    : 1
    hooks          : 0 (0 can block)
    telemetry      : https://otel.corp.internal (capturing prompt content)
    auth           : subscription via github

  Codex CLI
    managed config : none
    approval mode  : never
    bypass allowed : yes
    permission rules: 0 allow, 0 ask, 0 deny
    mcp servers    : 1
    hooks          : 0 (0 can block)
    telemetry      : off
    auth           : unknown

  ... and Claude Code and Gemini CLI

Findings (30)

  [HIGH] GitHub Copilot CLI: Exporting prompt or tool content
        Prompts and tool arguments routinely contain credentials, customer data
        and source code. Exporting them turns the telemetry pipeline into a
        system that inherits the sensitivity of everything the agent touches.
        evidence: https://otel.corp.internal

  [HIGH] Codex CLI: Running with no sandbox
        The agent is configured for full access, so its shell commands and file
        operations run with the developer's own privileges against the whole
        machine, not a restricted workspace.
        evidence: sandbox mode: danger-full-access

  [HIGH] Gemini CLI: Administrator configuration exists but can be overridden
        The only administrator-authored configuration here is a file that any
        user setting overrides. That is more dangerous than having none, because
        someone wrote a policy and believes it is deployed, so nobody checks
        again, while every developer can ignore it.
```

*Real output, abridged. It comes from the sandbox the walkthrough builds, not from
anyone's laptop; run `./examples/walkthrough.sh` to reproduce it exactly.*

Every finding says what was observed, why it matters and what to do about it. There is
no score: a security team has to be able to argue with each one individually.

## Try it

```
curl -LO https://github.com/feysal07/reeve/releases/latest/download/reeve-linux-amd64.tar.gz
tar -xzf reeve-linux-amd64.tar.gz
./reeve-linux-amd64/reeve scan
```

Builds for Linux, macOS and Windows on the
[releases page](https://github.com/feysal07/reeve/releases), with checksums and signed
build provenance. One static binary, no runtime, no dependencies.

To see all four planes end to end, run the walkthrough. It builds a throwaway
sandbox of four badly configured agents and asserts 121 checks against it. The
sandbox has a home directory of its own, so it reads nothing you have installed and
gives the same answer on every machine:

```
./examples/walkthrough.sh                                              # macOS, Linux
powershell -ExecutionPolicy Bypass -File .\examples\walkthrough.ps1    # Windows
```

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for the manual steps.

> A reeve was an official who governed on behalf of others, and answered for what
> happened on their watch.

## The problem

Enterprises now run several AI coding agents side by side. Each vendor ships its own
admin console, its own policy file, its own telemetry format and its own audit API, and
none of them can see the others. Security teams are asked to answer questions that span
all of them:

- Which agents are installed, and who approved them?
- What can each one read, write, execute and reach on the network?
- Which MCP servers are they connected to, and who owns those?
- What did an agent actually do, and can we prove it six months later?
- What is this costing, per team and per repository?

Reeve answers those questions once, across vendors, without sending your data to anyone.

## Scope

Reeve targets the agents below. Support is staged; see the roadmap.

| Agent | Discovery | Policy | Enforcement | Telemetry |
|---|---|---|---|---|
| Claude Code | **working** | **working** | **working** | **working** |
| GitHub Copilot CLI | **working** | **working** | **working** | **working** |
| OpenAI Codex CLI | **working** | **working** | **working** | **working** |
| Google Gemini CLI | **working** | **working** | **working** | **working** |
| Cursor | **working** | **working** | **working** | planned |
| OpenCode, Amp, Kiro | community adapters | | | |

Cursor is the odd one out, in a way worth knowing before you plan around it. Its only
administrator-owned file is a hooks file, so permissions, the approval mode, the
sandbox and the MCP list stay editable by the developer whatever an organisation
deploys. The guard is not the livelier of two layers there; it is the only one, which
is why compiling the baseline policy for Cursor reports every rule as guard-only while
the others manage at least one natively. Its hooks also fail open by default, so
`reeve policy compile` always writes `failClosed` and `reeve scan` reports a hook that
lacks it. Its usage data lives in Cursor's own service rather than in a local export,
so telemetry there means reading their API rather than receiving OTLP.

## Design principles

1. **Enforcement lives inside the agent, not in the network.** Two of the major agents
   cannot be proxied at all, and a gateway only ever sees model traffic, never the shell
   commands and file edits that actually carry risk. Reeve uses each vendor's own locked
   configuration as the floor, and a local fail-closed policy agent as the hook.
2. **Identity is free and core.** Single sign-on is how every event, cost record and
   policy decision is attributed. Charging for it would be charging for the product
   working at all.
3. **Self-hosted first.** The people who need this most cannot send agent transcripts to
   a third-party SaaS.
4. **Governance is an enabler.** The goal is not to stop developers using AI agents. It
   is to let security teams say yes, with limits they can prove.

## Status

Pre-alpha. Discovery works for Claude Code, GitHub Copilot CLI, Codex CLI, Gemini CLI
and Cursor:

```
reeve scan
```

It reads each agent's configuration, records whether every setting came from an
administrator-owned file or one the developer can edit, and reports findings that say
what was observed, why it matters and how to fix it. It is read-only and makes no
network calls. `--json` emits the full report; `--fail-on high` makes it usable as a
CI gate.

Enforcement works for all five. `reeve guard` is the hook handler an agent runs
before a tool call; it normalises the pending action, evaluates one policy that applies
to every agent, and answers in the shape that agent understands:

```
reeve policy check examples/policy/baseline.yaml
reeve policy test  examples/policy/baseline.yaml --command "rm -rf /var"
```

See [docs/ENFORCEMENT.md](docs/ENFORCEMENT.md) for the failure behaviour, which is the
part that determines whether enforcement is real.

To wire it into every agent on a machine without editing five files by hand:

```
reeve install --plan     # say what would change, and change nothing
reeve install            # dry run: records what it would have blocked
reeve install --enforce  # once the policy looks right
reeve uninstall
```

It merges into the developer's own configuration rather than replacing it, backs up
each file before the first change, and removes only what it added — a hook you wrote
yourself survives both directions. It will not rewrite Codex's `config.toml` when one
already exists, because that file is TOML with comments no round trip preserves; it
prints the snippet to paste and reports that agent as needing a manual step rather
than counting it as done.

`reeve policy compile` renders the same policy as each agent's own
administrator-owned configuration, so enforcement survives the guard being absent. It
reports which rules an agent can enforce natively and which need the guard, rather
than silently dropping what it cannot express.

`reeve posture` answers the same questions about a fleet. It reads a directory of
`reeve scan --json` output, one file per machine, and reports how many machines run
each agent, how many can still turn off prompting, and which findings are everywhere
rather than on one laptop:

```
reeve posture ./reports --fail-on high
```

It reads files rather than listening on a port: whatever already collects from your
machines has an owner and an audit trail, and a service whose job is to accept claims
about security state from the machines being judged would need both built again. Every
file is accounted for, including the ones it could not read, and a percentage always
names the population it is a percentage of.

`reeve mcp` reconciles the MCP servers agents are configured with against the ones you
have approved:

```
reeve mcp list  ./reports --as-registry > registry.yaml
reeve mcp check ./reports --registry registry.yaml --fail-on high
```

A server's name is a key the developer chose in their own file — anything at all can be
called `github` — so entries are matched on their command or URL, a name-only match is
reported as exactly that rather than as approval, and a server using an approved name
while running something else gets the loudest verdict there is.

`reeve collect` receives what agents report over OpenTelemetry, in either wire
encoding, normalises the three
vendors' incompatible metric names into one model, computes cost centrally from tokens
at your rates, and resolves team attribution from a mapping you control rather than
from an attribute the client asserts. `reeve report` turns that into cost and usage by
team, agent, user, repository and model, joined with the guard's decision log:

```
reeve collect --store ./events.jsonl --teams ./teams.yaml
reeve report  --store ./events.jsonl --decisions ./decisions.jsonl --since 168h
```

That cost figure is what the usage **would** cost at your rates. For an organisation
paying for seats in advance it is not money leaving, so declare how you actually pay
and the report separates the two — and measures consumption against the allowance your
plan includes, per seat as well as in total:

```
  organisation : 323.3M of 580.0M used (56%) across 25 seat(s)
  over a seat  : 1 person(s) past the 100.0M a single seat includes
                 heavy@example.com                  288.1M (288%)
```

The organisation is comfortable. One person is at 288% of the most generous seat it
holds. A fleet total shows you the first line and stops.

The same figures export to Prometheus from `reeve collect --prices`, because nobody
reads a report at two in the morning, and `reeve report --fail-on` turns them into a
build gate the way `scan` and `posture` already are. A policy rule can enforce on them
directly, reading what the plan includes rather than carrying a copy of the number that
goes stale the moment somebody upgrades a seat.

The decision log is the half of the record no vendor can supply. An agent reports what
it did; an action the guard refused never happened as far as the agent is concerned.

That makes it the file most worth editing, so it can be sealed and checked:

```
reeve audit seal   /var/log/reeve/decisions.jsonl
reeve audit verify /var/log/reeve/decisions.jsonl
```

A seal records how many lines the log held and what they hashed to; each seal names the
one before it. `verify` exits non-zero if a line was changed, inserted, reordered or
deleted, and says which interval. Nothing written since the last seal is covered, and
a log that has never been sealed reports as *not verified* rather than as clean.

See [docs/TELEMETRY.md](docs/TELEMETRY.md). Prompt and response content is never
stored, whatever an agent is configured to send.

To see it working on one machine, there is a compose stack — collector, Prometheus
and Grafana, one command:

```
cd deploy/compose && docker compose up -d
```

Everything binds to 127.0.0.1, because the collector has no authentication and cannot
have any: it accepts OTLP from agents that have no credential to present. See
[deploy/compose](deploy/compose) for what that means before you change a port.

To run the collector in Kubernetes, there is a Helm chart:
[deploy/helm/reeve-collector](deploy/helm/reeve-collector). It deploys a single
writer against a persistent volume, and refuses to render four configurations that
would come up green and produce a quietly wrong audit trail.

## Licence

Apache-2.0. See [LICENSE](LICENSE), and
[docs/FREE-FOREVER.md](docs/FREE-FOREVER.md) for what will never move behind a paywall.

To contribute, see [CONTRIBUTING.md](CONTRIBUTING.md); contributions are accepted under
the DCO, not a CLA. To report a security problem, see [SECURITY.md](SECURITY.md) rather
than opening an issue.
