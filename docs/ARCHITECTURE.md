# Architecture

Reeve is built as three planes. Only the first exists today.

## 1. Discovery

`reeve scan` reads the local configuration of every agent it supports and produces a
normalised report. It is read-only, makes no network calls, and requires no server.

Each agent is handled by an **adapter** under `internal/adapter`. An adapter is the only
place in the codebase permitted to know a vendor's file formats and field names.
Everything above it works on the vendor-neutral types in `internal/model`.

The single most important thing an adapter records is **scope**: whether a setting came
from a file an administrator owns or one the developer can edit. A permission rule a
developer can delete is a default, not a control, and the report must never present the
two as equivalent.

`internal/findings` turns that normalised view into explainable observations. Findings
state what was observed, why it matters and what to do about it. They are deliberately
not reduced to a single score, because a security team has to be able to argue with each
one individually.

## 2. Policy and enforcement (planned)

One policy, authored once, compiled into each vendor's own locked configuration format,
plus a signed policy bundle for a local agent that acts as the hook for every supported
product.

Enforcement lives inside the agent rather than in the network. Two of the major agents
cannot be proxied at all, and a gateway only ever sees model traffic, never the shell
commands and file edits that carry the real risk. Where a vendor's hook mechanism fails
open on timeout, the local agent evaluates against a cached bundle so it can still fail
closed.

## 3. Telemetry and audit (planned)

Three ingestion paths into one event model: client-pushed OpenTelemetry from agents that
emit it, server-pushed telemetry from vendors that only export from their own cloud, and
pull adapters against vendor audit and usage APIs. Cost is computed centrally from token
counts, because most agents emit no cost figure and the ones that do emit an estimate.

## Adding an agent

Implement `adapter.Adapter` in a new package under `internal/adapter`, register it in
`cmd/reeve/main.go`, and ship contract tests pinned to specific agent versions. Vendors
change these formats often, and the tests are what tell you when they have.
