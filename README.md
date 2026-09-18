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
| Claude Code | planned v0.1 | planned v0.1 | planned v0.1 | planned v0.1 |
| GitHub Copilot CLI | planned v0.1 | planned v0.1 | planned v0.1 | planned v0.1 |
| OpenAI Codex CLI | planned v0.2 | planned v0.2 | planned v0.2 | planned v0.2 |
| Google Gemini CLI | planned v0.3 | planned v0.3 | planned v0.3 | planned v0.3 |
| Cursor | planned v0.3 | planned v0.3 | planned v0.3 | planned v0.3 |
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

## Status

Pre-alpha. Nothing works yet. Follow the repository for the first release.

## Licence

Apache-2.0. See [LICENSE](LICENSE), and
[docs/FREE-FOREVER.md](docs/FREE-FOREVER.md) for what will never move behind a paywall.
