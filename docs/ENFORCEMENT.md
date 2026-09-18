# Enforcement

`reeve guard` decides whether one action may proceed. An agent runs it before a tool
call, hands it a description of what it is about to do, and obeys the answer.

## Why enforcement lives inside the agent

The obvious design is a proxy: put Reeve between the agent and the model and inspect
the traffic. It does not work.

Two of the major agents cannot be pointed at a third-party endpoint at all. More
fundamentally, model traffic is the wrong place to look. What carries risk is not the
tokens going to the model, it is the shell command, the file write and the MCP call
that happen afterwards on the developer's machine. A proxy never sees those.

So Reeve enforces at the only point where an action is both fully described and has
not happened yet: the agent's own pre-tool hook.

## How a decision is made

1. The agent runs `reeve guard --agent <id>` and writes a JSON description of the
   pending action to its stdin.
2. The guard normalises that into a vendor-neutral action. A shell command is a shell
   command whether the agent calls the tool `Bash`, `shell` or `local_shell`.
3. The policy is evaluated. Every rule is considered and the strictest match wins, so
   rule order is irrelevant and adding a rule can only tighten a policy.
4. The decision is written back in the shape that agent understands, and mirrored in
   the exit status.

The result is `allow`, `ask` or `deny`. `ask` does not block: it hands the decision to
the developer through the agent's own permission prompt.

## Failure behaviour

This is the part that determines whether enforcement is real.

| Situation | Decision | Why |
|---|---|---|
| No policy configured anywhere | allow | There is no operator intent to violate. |
| Policy file named but missing | **deny** | Someone configured enforcement and it is not working. |
| Policy present but invalid | **deny** | The operator's intent cannot be known, and pretending to enforce is worse than stopping. |
| Hook request unparseable | **deny** | An action that cannot be described cannot be judged. |
| Decision log unwritable | unchanged | Losing an audit line is not a reason to change a decision. |

Note the asymmetry between the first two rows. Absence of policy and failure of policy
are different things, and treating them the same would either block every machine that
has not been configured yet or silently disable enforcement wherever a file was
mistyped.

One caveat that cannot be fixed from this side: several agents treat a hook **timeout**
as permission to continue. The guard is therefore built to be fast and to touch neither
the network nor a server on the decision path. Policy evaluation is measured in
microseconds; process startup dominates, at roughly 100 to 200 milliseconds.

## Writing a policy

Start from [examples/policy/baseline.yaml](../examples/policy/baseline.yaml) and
validate it:

```
reeve policy check examples/policy/baseline.yaml
```

Then ask what it would do about a specific action, before it ever blocks a colleague:

```
reeve policy test examples/policy/baseline.yaml --command "rm -rf /var"
reeve policy test examples/policy/baseline.yaml --kind read --path "svc/.env"
reeve policy test examples/policy/baseline.yaml --mcp-server postgres-prod --mcp-tool query
```

`policy test` exits non-zero on a deny, so a team can assert its policy's behaviour in
CI and keep it honest as it grows.

A rule matches on the neutral action kind (`shell`, `read`, `write`, `fetch`, `mcp`),
on the agent's own tool name, on the command line, on file paths, on a fetch URL, or
on an MCP server and tool. Every field that is set must match, and a field with several
values matches if any one of them does.

Write a `reason` on every rule. A developer blocked without an explanation will find a
way around the hook, and will be right to.

## Rolling it out

Deploy in `--dry-run` first. The guard evaluates and logs exactly as it would in
enforcement, but always allows. Run it for a week, read the log, and fix the rules that
fire on ordinary work before anyone is actually stopped.

```
reeve guard --agent claude-code --dry-run --log /var/log/reeve/decisions.jsonl
```

Where the policy lives, strongest first:

1. `REEVE_POLICY`
2. `/etc/reeve/policy.yaml`, or `%ProgramData%\Reeve\policy.yaml` on Windows
3. `~/.reeve/policy.yaml`

Only the second of these is a control. A policy a developer can edit is a default. Put
the real one in the machine-wide location, owned by root or Administrators, and
`reeve scan` will tell you whether the file is still writable by the user.

## Wiring it into each agent

In every case the hook configuration must itself be administrator-owned. A hook a
developer can remove is advice, not enforcement.

### Claude Code

In the managed settings file (`/etc/claude-code/managed-settings.json`, or the
equivalent on macOS and Windows):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "reeve guard --agent claude-code --log /var/log/reeve/decisions.jsonl"
          }
        ]
      }
    ]
  },
  "allowManagedHooksOnly": true
}
```

`allowManagedHooksOnly` stops a developer adding their own hooks alongside yours.

### GitHub Copilot CLI

Use the policy hook directory, which is the only place a developer cannot disable:
`/etc/github-copilot/policy.d/reeve.json`, or
`%ProgramData%\GitHub\Copilot\policy.d\reeve.json` on Windows.

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "type": "command",
        "exec": "reeve",
        "args": ["guard", "--agent", "copilot-cli", "--log", "/var/log/reeve/decisions.jsonl"],
        "timeoutSec": 10
      }
    ]
  }
}
```

Use the `exec` form rather than an HTTP hook. Copilot's HTTP hooks fail open on
timeout, and so does every hook type when it times out, so keeping the decision local
and fast is the only way to keep it reliable.

### Codex CLI

In `/etc/codex/requirements.toml`, or `%ProgramData%\OpenAI\Codex\requirements.toml`:

```toml
allow_managed_hooks_only = true

[[hooks.PreToolUse.hooks]]
type = "command"
command = "reeve"
args = ["guard", "--agent", "codex-cli", "--log", "/var/log/reeve/decisions.jsonl"]
```

Codex also expresses administrator control as constraints on what a developer may
choose. Set those too, since a policy hook is of limited use if the agent can be
started with no sandbox:

```toml
allowed_approval_policies = ["on-request"]
allowed_sandbox_modes = ["read-only", "workspace-write"]
```

## The decision log

Each decision appends one JSON line: what was attempted, what was decided, which rule
decided it, and how long evaluation took. It records no prompt text and no file
contents.

```json
{"time":"2026-09-18T15:42:03Z","agent":"claude-code","kind":"shell",
 "command":"rm -rf /data","effect":"deny","ruleId":"destructive-delete",
 "policyFile":"/etc/reeve/policy.yaml","elapsedMicros":31}
```

This is the local half of an audit trail. It records what the agent tried to do on the
machine, which no vendor's audit API captures, because none of them can see a tool call
that was refused before it ran.
