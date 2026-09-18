# Reeve

**A vendor-neutral, self-hosted control plane for AI coding agents.**

Reeve discovers which AI coding agents are installed across your organisation, enforces
one policy across all of them, and gives you a single audit trail and cost view, using
your own identity provider.

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
| Google Gemini CLI | planned | planned | planned | planned |
| Cursor | planned | planned | planned | planned |
| OpenCode, Amp, Kiro | community adapters | | | |

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

## Try it

```powershell
.\examples\walkthrough.ps1
```

Builds the binary, creates a sandbox with three deliberately badly configured agents,
and runs all four planes end to end. See [docs/QUICKSTART.md](docs/QUICKSTART.md) for
the manual steps.

## Status

Pre-alpha. Discovery works for Claude Code, GitHub Copilot CLI and Codex CLI:

```
reeve scan
```

It reads each agent's configuration, records whether every setting came from an
administrator-owned file or one the developer can edit, and reports findings that say
what was observed, why it matters and how to fix it. It is read-only and makes no
network calls. `--json` emits the full report; `--fail-on high` makes it usable as a
CI gate.

Enforcement works for all three. `reeve guard` is the hook handler an agent runs
before a tool call; it normalises the pending action, evaluates one policy that applies
to every agent, and answers in the shape that agent understands:

```
reeve policy check examples/policy/baseline.yaml
reeve policy test  examples/policy/baseline.yaml --command "rm -rf /var"
```

See [docs/ENFORCEMENT.md](docs/ENFORCEMENT.md) for how to wire it into each agent, and
for the failure behaviour, which is the part that determines whether enforcement is
real.

`reeve policy compile` renders the same policy as each agent's own
administrator-owned configuration, so enforcement survives the guard being absent. It
reports which rules an agent can enforce natively and which need the guard, rather
than silently dropping what it cannot express.

`reeve collect` receives what agents report over OpenTelemetry, normalises the three
vendors' incompatible metric names into one model, computes cost centrally from tokens
at your rates, and resolves team attribution from a mapping you control rather than
from an attribute the client asserts. `reeve report` turns that into cost and usage by
team, agent, user, repository and model, joined with the guard's decision log:

```
reeve collect --store ./events.jsonl --teams ./teams.yaml
reeve report  --store ./events.jsonl --decisions ./decisions.jsonl --since 168h
```

The decision log is the half of the record no vendor can supply. An agent reports what
it did; an action the guard refused never happened as far as the agent is concerned.

See [docs/TELEMETRY.md](docs/TELEMETRY.md). Prompt and response content is never
stored, whatever an agent is configured to send.

## Licence

Apache-2.0. See [LICENSE](LICENSE), and
[docs/FREE-FOREVER.md](docs/FREE-FOREVER.md) for what will never move behind a paywall.
