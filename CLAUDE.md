# Working on Reeve

Reeve is a vendor-neutral, self-hosted control plane for AI coding agents: one static
Go binary covering discovery, policy compilation, enforcement and telemetry. See
`README.md` for what it does and `CONTRIBUTING.md` for how to contribute. This file is
for agents and tooling working in this repository.

British spelling throughout, in prose and in identifiers (`organisation`, `normalise`).

---

## Git workflow

- **Feature work goes on a branch and lands via a pull request.** Branch off `main`,
  commit there, push, open the PR with `gh pr create`. Do not commit new features
  directly to `main`.
- **Commit messages are prose.** Present-tense subject line, body explaining the
  reasoning and what was found — not a list of files touched. Run `git log` for the
  house style.
- Ask before pushing or opening a PR. Both are outward-facing.

---

## The design spine

One idea runs through this project, and nearly every bug found so far is an instance
of it:

> **Every significant failure here is an invisible failure that looks like success.**

Real examples: one `//` comment in a settings file made `scan` report 0 deny rules
instead of 2; a backup written on Windows landed in an NTFS alternate data stream, so
it silently did not exist; `UnmarshalYAML` carried the yaml.v2 signature that yaml.v3
never calls, so every allowance period parsed as zero and the whole feature printed
nothing; a policy with only a `tokens:` budget panicked the guard on every action, and
a crashed hook is not a refusal.

When reviewing or designing, the question is not "is this correct?" but **"if this were
wrong, what would I see?"** If the answer is "the same thing I see now", that is the bug.

### Fail-closed asymmetry

Load-bearing; do not flatten it into a single rule.

- An **absent** policy allows — there is no expressed intent to violate.
- A policy that **exists and cannot be read** denies.
- An input a rule **depends on** and cannot read denies. An unreadable event store is
  not a spend of zero; an allowance nobody could resolve is not one nobody has touched.
- A **partially-read window** denies when the visible part is under the threshold: a
  partial total is a floor, and a budget compared against a floor permits.

### Invariants

- **Nothing about a person in the metrics endpoint.** Identities live in the event
  store; Prometheus is scraped by systems with far wider read access.
- **Prompt and response content is never stored** in telemetry. Ever.
- **Credential values are never read** — names only.
- **Team attribution is never client-asserted**; it resolves from an operator-owned
  mapping.
- **Equivalent cost is not money.** Tokens times rates is what usage *would* cost.
- **A per-seat allowance is not a fleet total.** An org can sit at 56% while one person
  is at 288% of their seat.
- **No outbound calls to vendors.** Reeve never reads a vendor console and never
  proxies anyone's OAuth tokens.

---

## Engineering conventions

1. **Every guard gets a test, and every test gets mutation-tested.** After writing a
   test, programmatically break the guard it covers and confirm the suite fails. A
   surviving mutation means a missing test or a genuinely redundant guard — and if
   redundant, say so in a comment. `AllowanceMatch.percent` documents exactly that.
2. **Comments explain the failure the code prevents, not what the code does.** Prefer
   the real incident. `internal/policy/command.go` and `internal/telemetry/billing.go`
   set the register.
3. **Test names are sentences.** `TestASharedPoolIsNotMistakenForOneSeatsAllowance`,
   not `TestLargestSeatLimit`.
4. **Validate at load time, where somebody is looking.** A declaration that cannot mean
   anything is refused when the file is parsed, not silently turned into zero.
5. **The walkthrough is the acceptance test.** Any user-visible feature gets checks in
   `examples/walkthrough.sh`, and the count is updated in `README.md` and
   `docs/QUICKSTART.md` (currently **104** in all three).
6. **Shipped examples and docs are loaded by a test.** `examples/telemetry/prices.yaml`,
   the YAML blocks in `docs/TELEMETRY.md`, `examples/policy/*.yaml` and the Grafana
   dashboard are all parsed by tests. Each of them broke silently at least once.

---

## Codebase map

```
cmd/reeve/          one file per subcommand; allowance.go bridges telemetry to policy
internal/policy/    vendor-neutral. Action, Match, Evaluate. Knows NO vendor formats.
internal/hook/      translates each vendor's hook payload into a policy.Action
internal/compile/   renders a policy as each agent's native config
internal/telemetry/ collect, store, OTLP decode, pricing, billing, report, metrics
internal/findings/  scan findings
internal/install/   hook registration per agent
internal/posture/   fleet aggregation
internal/audit/     decision-log sealing
internal/mcp/       MCP server reconciliation
internal/config/    JSON-with-comments reading, unknown-key detection
deploy/compose/     collector + Prometheus + Grafana quickstart
examples/           baseline, budget, loop-breaker, allowance, prices, walkthrough.sh
```

**Layering rule:** `internal/policy` must never import `internal/telemetry` and must
never know anything about a vendor. When a rule needs outside data it arrives
pre-resolved on the `Action` (`Action.History`, `Action.Spend`, `Action.Allowance`) and
a file under `cmd/reeve/` does the bridging. `cmd/reeve/allowance.go` is the worked
example.

**Hand-rolled on purpose:** the OTLP protobuf decoder
(`internal/telemetry/protobuf.go`, `protowire.go`) and the Prometheus exposition writer
(`metrics.go`), so the binary stays small enough to drop on every developer machine.
The bargain is that the canonical libraries are imported **by the tests** and used to
read our output back. Keep that bargain — never add them as non-test dependencies.

---

## Traps that have actually bitten

**Tooling**

- Bash heredocs collapse a doubled backslash into a single one in this environment. Use
  the `Write` tool for new files, or `chr(92)` in Python, or line-based edits.
- Backticks inside Go raw strings break compilation. Use single quotes in help text.
- MSYS path translation mangles container paths passed to `docker run`. Wrap the
  container-side command in `sh -c`.
- `$?` after a pipe reads the last command's status, not the one you meant.

**Go**

- `defer` cannot mutate a value-returning function's named local after the copy is made.
  Hit twice — `audit.Verify` and `AggregateWith`. Both now assign explicitly, with a
  comment saying why.
- yaml.v3 ignores the yaml.v2 `UnmarshalYAML(unmarshal func(any) error)` signature. It
  must be `UnmarshalYAML(value *yaml.Node) error`.
- `filepath.Base` is OS-specific. Reconciling a Windows path on a Linux CI runner
  reported every Windows machine as a mismatch; `internal/mcp` splits on both separators.

**Platform**

- A Windows path used as a filename creates an NTFS alternate data stream.
  `install.backupName()` uses basename plus a 4-byte sha256 hex instead.
- The compose stack crash-looped: a nonroot image against a root-owned named volume.
  An init service now chowns to 65532.

**Safety**

- **All `reeve install` testing runs against a sandboxed `HOME`/`USERPROFILE`**, never
  the real home. The walkthrough does this; keep it that way, or a demo that claims to
  touch nothing will quietly rewrite real agent configuration.

---

## Verifying a change

```bash
go build ./... && go test ./...
```

```bash
bash examples/walkthrough.sh --quiet
```

`go test ./...` covers 19 packages. The walkthrough is 104 checks and must end with 0
failures.
