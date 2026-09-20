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

### Gemini CLI

Gemini has two configuration systems, and the guard belongs in the settings file. In
`/etc/gemini-cli/settings.json`, or `%ProgramData%\gemini-cli\settings.json`:

```json
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "*",
        "hooks": [
          {
            "name": "reeve-guard",
            "type": "command",
            "command": "reeve guard --agent gemini-cli --log /var/log/reeve/decisions.jsonl"
          }
        ]
      }
    ]
  },
  "security": { "disableYoloMode": true }
}
```

The event is `BeforeTool`, not `PreToolUse`, and the reply is read from a field spelled
`decision` rather than `permissionDecision`. A reply in any other agent's shape parses
as JSON, carries nothing Gemini recognises, and is treated as the hook having no
opinion, so the tool runs. That is why `--agent` is required and why an unrecognised
value is refused rather than guessed at.

**Gemini hooks cannot ask.** `BeforeTool` returns allow or deny and has no third
option. A rule whose decision is `ask` is therefore refused by the guard, with a reason
saying so, rather than allowed: turning a rule that demanded a human decision into one
that needs none would remove the control the day Gemini was added, and nothing would
report it. Gemini's policy engine *can* prompt, and `reeve policy compile` writes ask
rules into it, so that is where they belong. If you would rather those rules prompted
than blocked, deploy the compiled policy file and leave the guard unregistered.

### Cursor

Cursor's only administrator-owned file is its hooks file. In `/etc/cursor/hooks.json`,
`/Library/Application Support/Cursor/hooks.json`, or
`%ProgramData%\Cursor\hooks.json`:

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "command": "reeve guard --agent cursor --log /var/log/reeve/decisions.jsonl",
        "type": "command",
        "timeout": 10,
        "failClosed": true
      }
    ]
  }
}
```

**`failClosed` is the important key, and it defaults to false.** Without it a crash, a
timeout, or an exit code Cursor does not recognise is logged and the action is allowed.
Those are the conditions under which a machine is least likely to be in a state anyone
has checked, so a hook deployed without it stands down precisely when it mattered.
`reeve policy compile` always writes it, and `reeve scan` raises
`policy.hook-fails-open` against a blocking hook that lacks it.

**One event, not four.** Cursor has purpose-built permission hooks for shell commands,
file reads and MCP calls, and a generic `preToolUse` that fires for every tool type.
Only `preToolUse` sees a file being *written*: there is a `beforeReadFile` but no
`beforeFileEdit`, and `afterFileEdit` runs once the edit has happened. Registering a
specific event alongside the generic one runs both for a single action, which decides
the same thing twice and writes it to the decision log twice, so every count in
`reeve report` would be double what happened.

**Cursor sends more than the guard needs.** Every hook receives the developer's email
address, a path to the conversation transcript and, for a file read, the entire
contents of the file. None of it is read into the action, because the guard writes a
decision log and anything the action carries lands on a developer's disk.

## Matching a command: what it runs, not what it carries

Two matchers look at a command line, and the difference between them was measured
rather than guessed.

```yaml
match:
  commandRuns:      ["rm -rf"]   # what the command executes
  commandContains:  ["rm -rf"]   # anywhere in the line, data included
```

The first real trial of this tool recorded fourteen hours of one developer's ordinary
work: 864 actions and 54 rule firings. **Thirty-two of the fifty-four matched text
that was never going to execute.** A git commit whose message explained a fix and
therefore quoted `rm -rf`. Ten test fixtures shaped like
`echo '{"command":"rm -rf /"}' | reeve guard`. Python here-documents editing source
files that mention `kubectl` or `git push --force`. In every case the command being
run was `git`, `echo` or `python`.

`commandRuns` removes here-document bodies before matching, because a here-document is
input to a program rather than a command. Everything else is matched as before,
including quoted arguments — `sh -c "rm -rf /"` and `cat ".env"` both put the
interesting text in an argument, and both matter.

**Neither is a boundary against someone trying to get past it.** A here-document fed
to an interpreter is executed by that interpreter, so `python - <<'PY'` carrying
`os.system("rm -rf /")` is not matched by `commandRuns`. That was already true of
anything built at runtime, base64-encoded or assembled from variables. Matching text
in a command line catches mistakes and casual actions, never a determined evader, and
the only thing this changes is how much ordinary work gets caught alongside them.

Neither compiles to native configuration. No vendor's permission syntax matches a
substring of a command line, and none of them strips here-document bodies first, so an
emitted rule would fire where a `commandRuns` rule says it must not — a compiler
quietly making a rule stricter than it was written.

## Replaying a log against a changed policy

```
reeve policy replay ./decisions.jsonl --policy new-baseline.yaml
```

Run the guard in dry run for a week, then find out what a rule change would have done
to that week before anyone has to live with it.

```
  outcome    : 864 actions replayed: 16 stricter, 49 looser, 799 unchanged
  stopped    : 0  (was 41)
  questioned : 50  (was 13)

  Rule                          before   after   change
    destructive-delete              41      25   -16
    production-infrastructure        6       0   -6  <- stops firing entirely
```

The counts that matter are **stopped** and **questioned**. A rule moved from deny to
ask fires exactly as often and is an entirely different thing to work under, and a
firing count cannot tell you that.

Counting rules replay properly, because the log *is* the history they count from: each
record is evaluated against the ones before it, as at its own recorded time rather than
as at now. **Budgets cannot be replayed at all** — spend lives in the event store, so
there is nothing in a decision log to total, and replay says so rather than reporting
that no budget was ever exceeded.

## Circuit breakers: matching on what already happened

Every rule above is a pure function of the action in front of it. One is not.

```yaml
- id: runaway-tool-loop
  decision: ask
  match:
    repeated:
      same: tool        # tool | command | any
      within: 10m
      moreThan: 50
      scope: session    # session | machine
```

This is for the failure that costs the most and looks least like an attack: an agent
stuck retrying, doing a reasonable thing several hundred times. Nothing about the four
hundredth call is suspicious on its own, which is exactly why no other rule catches it.

The count comes from the guard's own decision log, so a counting rule has a
prerequisite the others do not: run the guard with `--log`, or set
`REEVE_DECISION_LOG`. `reeve policy check` says so when a policy needs it.

**A rule that cannot count refuses.** This is the same asymmetry as the policy file one
level up, and it points the other way for a reason. An absent *policy* allows, because
there is no expressed intent to violate. An input that a rule which *does* exist
depends on, and which cannot be read, denies — because an empty history is not evidence
that nothing happened. A log that simply does not exist yet is treated as empty rather
than unreadable: nothing has run because nothing has run.

The rule fires on the call that would take the total past the line, not one call later:
the action being decided is not itself counted.

**No agent can express this natively**, so a counting rule is always guard-only, and
never partial. Emitting the rest of the match without the count produces a different
and stricter rule — "deny curl after fifty tries" would compile to "deny curl" — so the
compilers emit nothing for it and say why.

See [examples/policy/loop-breaker.yaml](../examples/policy/loop-breaker.yaml). It is
deliberately not in the baseline: the baseline is the first thing anyone deploys and
must work without a decision log.

## Budgets: matching on what has already been spent

The other rule that is not a function of the request in front of it.

```yaml
- id: daily-cap
  decision: deny
  match:
    spend:
      within: 24h
      moreThan: 50.00   # US dollars
      scope: machine    # session | machine
```

The total comes from the event store `reeve collect` writes, so a budget has its own
prerequisite: run the guard with `--store`, or set `REEVE_EVENT_STORE`.
`reeve policy check` says so when a policy needs it.

**A budget that cannot read the store refuses**, for the same reason a counting rule
that cannot count refuses: zero recorded spend and unreadable spend are not the same
claim. A store that does not exist yet is treated as empty, because the collector has
not written anything.

**It refuses on a partial answer too.** The guard reads the tail of the store rather
than all of it. If the store is busy enough that the read stops before reaching the
start of the window, the total in hand is a floor rather than a figure — and a budget
compared against a floor fails in the permissive direction, on exactly the machine
where spend is highest. So a truncated window that is still under the limit denies and
says to rotate the store or shorten the window. A truncated window already over the
limit is not ambiguous and denies by the rule itself: unread older events cannot bring
a total back down.

It fires on the first action *after* the line was crossed, not on the one that crosses
it. What a pending action will cost is not known until it has run.

### Two limits to understand before relying on it

**It is soft, and it lags.** Cost reaches the store through each agent's own telemetry
export, which is batched. The figure the guard reads is behind real spend by that
interval, so a budget catches a runaway within about a minute rather than stopping the
request that crossed the line. The only hard ceilings that exist are the ones a vendor
enforces on its own side of the API.

**It does not cover every agent, and that gap is silent.** An agent that cannot be
configured to export usage to an endpoint you choose contributes nothing to the store.
Its spend reads as zero, stays under every threshold, and the rule never fires. Nothing
refuses and nothing complains, which is the most convincing way for a control to be
absent.

Because of that, `reeve policy compile` reports a budget on such an agent as
**`unenforceable`** rather than `guard-only`. The three other statuses are a promise:
`guard-only` means deploy the guard and the rule holds. This one means no layer covers
it, deploying the guard will not change that, and the rule must either be dropped for
that agent or the gap accepted deliberately.

```
Coverage: 0 enforced natively, 0 partially, 0 by the guard only, 2 NOT ENFORCED ANYWHERE
```

`scope: machine` means every event in the store the guard was given. That is only this
machine's spend if the store is this machine's, so point the guard at a local one. The
guard does not claim a boundary it cannot check: events carry a session, an identity
and a repository, and nothing that names a machine.

See [examples/policy/budget.yaml](../examples/policy/budget.yaml). Like the loop
breaker, it is deliberately not in the baseline.

## Knowing what an action actually targets

A rule can only be as good as what it can see. Matching the text "--context prod"
catches the developer who was explicit and misses the one who ran
`kubectl config use-context prod` an hour ago and now types `kubectl delete deploy api`.
The second is the more dangerous case, and no amount of care with substrings will find
it.

So the guard resolves the target before evaluating. It reads the command first, because
an explicit flag is what the developer actually asked for, and falls back to the tool's
own current state, which is what will happen if they said nothing:

| Tool | From the command | From ambient state |
|---|---|---|
| kubectl | `--context`, `-n`, `--namespace` | current-context and its namespace in the kubeconfig, honouring `KUBECONFIG` |
| helm | `--kube-context`, `--namespace` | the same |
| terraform | `-var-file`, `workspace select X` | the workspace selected in `.terraform/environment` |

A registry you control maps those identifiers to environments:

```
reeve guard --agent claude-code --resources /etc/reeve/resources.yaml
```

See [examples/resources/resources.yaml](../examples/resources/resources.yaml). A rule
then matches the environment rather than the words:

```yaml
match:
  kind: [shell]
  environment: [production]
```

Two properties worth knowing.

**Unknown is a value, not a silence.** A target that cannot be resolved is reported as
`unknown`, and a rule can match on it deliberately. The baseline does exactly that, with
its own rule and its own reason, because an unresolvable target is where a control is
most likely to be wrong and the honest thing is to say so rather than let it pass.

**An absent registry does not fail closed.** Unlike policy, most machines will not have
one, and every rule that does not mention an environment still works. So a missing or
unreadable registry leaves everything `unknown` rather than stopping work.

Resolution reads local files only and costs roughly a millisecond, which stays well
inside every agent's hook timeout.

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

### Proving it has not been edited

The decision log is the most valuable file this tool writes and the one most worth
editing, and until you seal it the only answer to "how do you know these were not
changed afterwards" is to trust the file.

```
reeve audit seal   /var/log/reeve/decisions.jsonl   # record what it holds now
reeve audit verify /var/log/reeve/decisions.jsonl   # check it against every seal
```

`seal` appends one line to `decisions.jsonl.chain`: how many lines the log held and
what they hashed to. Each seal names the one before it, so the sidecar is itself a
chain. `verify` recomputes and exits 2 if anything differs, so it works as a gate.

Run `seal` on a schedule — hourly from cron, at the end of a session, or in the job
that ships the log somewhere else.

**Why sealing and not a hash in every record.** The obvious design is each line linking
to the one before it. Every guard invocation is a separate short-lived process
appending with `O_APPEND` and no lock, and agents run tools concurrently, so two
processes would read the same last line and write two records claiming the same
predecessor. A verifier cannot tell that fork from an inserted record, and a tamper
detector that cries tamper on a busy machine is one nobody runs twice. It would also
put a read of a growing file on the path that has to answer before the agent times
out. Sealing leaves the guard's hot path untouched and has no concurrency to lose.

**What a seal proves.** Between two seals: that no line was changed, inserted, removed
or reordered. The running hash covers every byte in order, and the line count is
recorded separately, which is what catches deletion from the end — a hash chain alone
cannot, because a prefix of a valid chain is a valid chain. With several seals, a break
is localised to the interval between two of them rather than only to "somewhere".

Sealing a log whose sealed prefix has changed **refuses**. Otherwise the obvious move
after an edit is to seal again, which would leave a sidecar that passes and destroy the
only evidence the edit happened.

**What it does not prove.** Nothing written since the last seal is covered by anything;
that gap is as wide as your sealing interval. And a sidecar sitting beside the log it
seals is evidence only against someone who did not think to change both — copy it
somewhere the machine writing the log cannot reach. That is a property of where you put
it, not of this code.

A log that has never been sealed is reported as **not verified**, and exits 2. "No
breaks found" is true of it and means nothing, and that is exactly what a clean log
looks like too.

## Compiling the policy into native configuration

The guard is one layer. It is a process, and a process can be missing, misconfigured
or skipped by starting an agent differently. `reeve policy compile` renders the same
policy as each agent's own administrator-owned configuration, which is what remains
when the guard is not running.

```
reeve policy compile examples/policy/baseline.yaml --platform linux
reeve policy compile examples/policy/baseline.yaml --out ./dist --platform linux
```

It writes managed settings for Claude Code, managed settings plus a policy hook file
for Copilot CLI, and a requirements file for Codex CLI. The `settings` block of the
policy supplies the posture: the bypass lock, the sandbox requirement, the telemetry
destination, the MCP allow list and the guard registration.

### Read the coverage report

Native configuration is less expressive than the guard, and how much less depends on
the agent. Most match a command by its leading tokens or a path by a glob, cannot
match a substring in the middle of a command line, and do not understand the neutral
action kinds. Gemini's policy engine is the exception: it takes a regular expression
and an `ask_user` decision, so it carries rules the others cannot.

So the compiler reports what happened to every rule:

| Status | Meaning |
|---|---|
| `native` | The agent's own configuration enforces this. It holds with the guard absent. |
| `partial` | Some of the rule compiled. The guard covers the rest. |
| `guard-only` | Nothing about this rule can be expressed natively. |

Compiling the shipped baseline reports, out of eleven rules:

| Agent | native | partial | guard-only |
|---|---|---|---|
| Claude Code | 1 | 0 | 10 |
| GitHub Copilot CLI | 1 | 0 | 10 |
| Codex CLI | 1 | 0 | 10 |
| Gemini CLI | 6 | 2 | 3 |
| Cursor | 0 | 0 | 11 |

Those numbers are not a defect in the compiler. They are the honest measure of how
much of a real policy each agent can enforce by itself, and they are the reason both
layers are deployed together.

Cursor scores zero for a different reason from everyone else's, and the distinction
matters. Elsewhere a rule is guard-only because the vendor's permission syntax cannot
express its shape. On Cursor the shape is irrelevant: there is no administrator-owned
file to put a permission rule in at all. The guard is the only layer there, and the
compiled hooks file is the only thing an organisation can deploy that a developer
cannot edit.

Gemini scores higher because its rules take a regex, so the baseline's substring
matching survives translation. It is not a clean sweep: three rules still need the
guard, two of them because they combine a command pattern and a substring with AND,
and Gemini tests one condition per rule. Emitting both as separate rules would match
either instead of both, turning a narrow prompt about force-pushing to a protected
branch into one that fires on any command containing " main". The compiler reports
those as guard-only rather than shipping a rule that shares a name with the
operator's intent and not its meaning.

A rule is never quietly narrowed to make it fit. A rule written to catch `rm -rf`
anywhere would become a rule catching it only at the start of a command, which is a
weaker rule wearing the same name. The compiler refuses that trade and reports the
rule as guard-only instead.

Allow rules are never emitted. Adding them to an agent's allow list would widen what
it permits, and a compiled policy may only ever narrow.

Use `--strict` in CI to fail when any rule is not fully covered natively, if your
organisation needs that guarantee.

### Deploy both layers

```
reeve policy compile policy.yaml --out ./dist --platform linux
# distribute ./dist through MDM or configuration management,
# owned by root, then confirm with:
reeve scan
```

`reeve scan` reads the result back and will tell you whether the file you deployed is
still writable by the developer, which would make it a default rather than a control.
