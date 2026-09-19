# Quickstart

Two ways to see Reeve work. The scripted walkthrough takes a minute and exercises
everything. The manual steps below take longer and show you what each command does on
its own.

Neither touches your real agent configuration. Fake Copilot and Codex installations are
created in a sandbox and pointed at with `COPILOT_HOME` and `CODEX_HOME`, which both
agents honour. Your Claude Code configuration is read, never written.

## The scripted walkthrough

On macOS or Linux:

```
./examples/walkthrough.sh
```

On Windows. Unsigned scripts are blocked by default, so run it like this:

```
powershell -ExecutionPolicy Bypass -File .\examples\walkthrough.ps1
```

`-ExecutionPolicy Bypass` applies to that one invocation only and changes nothing on
your machine. If your policy already allows local scripts, `.\examples\walkthrough.ps1`
works on its own.

The two are the same walkthrough in two languages and assert the same checks. CI runs
the shell one on Linux and macOS and the PowerShell one on Windows, so neither quietly
stops working while the other is maintained.

Either builds the binary, creates a sandbox with four deliberately badly configured
agents, and runs all four planes in order: discovery, policy, enforcement, telemetry.
Add `--keep-sandbox` (or `-KeepSandbox`) to keep the artifacts.

The sandbox has a home directory of its own, which it points the agents at for the
duration. Nothing you have installed is read, and the counts below are the same
whatever is on the machine running it.

It ends with a summary like `All 44 checks passed.` and exits non-zero if any did not,
so it doubles as a smoke test. Add `--quiet` (or `-Quiet`) for just the checks.

The shell version uses `jq` or `python3` to read the scan's JSON. With neither
installed it says which checks it skipped rather than dropping them quietly.

The collector binds to a port the operating system picks, so an existing collector on
4317 or 4318 does not clash. That matters if you run the claude-code-otel stack.

Expect roughly this:

- **30 findings** across four agents, including a Codex install running with no
  sandbox and no prompting, a Copilot install exporting prompt content, and a Gemini
  install whose administrator file the developer has already overridden.
- **Ten enforcement decisions**, including Gemini and Cursor, which name their tools,
  their events and the field in their reply differently from everyone else. Cursor
  names no tool at all for a shell command, so its kind comes from the event.
- **Five failure cases**: an unparseable policy denies, an absent policy allows, an
  unreadable request denies, and an agent name Reeve does not recognise denies rather
  than guessing at the shape of a reply.
- **Two assertions that must pass**: a prompt sent to the collector does not reach the
  store, and a client-asserted team attribute is ignored.
- **A cost report** showing $1.31 computed from tokens against the agents' own claim of
  $1.42, broken down by team, agent, user, repository and model.

If a check fails, the summary names it and prints why. Send that block along with the
step it failed in; everything else in the output is context you do not need to read.

## Manual steps

Build once and put the binary on your PATH:

```
go build -o bin/reeve ./cmd/reeve
```

### 1. Discovery

```
reeve scan
```

Reads every supported agent's configuration and reports what it found. Add `--dir` to
treat another directory as the project root, `--json` for the full report, and
`--fail-on high` to use it as a CI gate.

The column that matters is `managed config`. Anything a developer can edit is a
default, not a control, and the findings say so.

### 2. Policy

```
reeve policy check examples/policy/baseline.yaml
```

Then ask what it would do, before it blocks a colleague:

```
reeve policy test examples/policy/baseline.yaml --command "rm -rf /var/data"
reeve policy test examples/policy/baseline.yaml --kind read --path "svc/.env"
reeve policy test examples/policy/baseline.yaml --command "go build ./..."
```

A deny exits 2, so these work as assertions in CI.

### 3. Compile

```
reeve policy compile examples/policy/baseline.yaml --platform linux
```

Renders the policy as each agent's own administrator-owned configuration. Add `--out`
to write the files.

Read the coverage report rather than the files. It reports one rule enforced natively
and eight guard-only, because the baseline leans on substring matching that no agent's
permission syntax can express. That is the honest measure of how much of a real policy
an agent can enforce by itself, and the reason both layers are deployed together.

### 4. Enforcement

The guard is what an agent runs before a tool call. You can drive it by hand with the
same payload an agent would send:

```
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | reeve guard --agent claude-code --policy examples/policy/baseline.yaml
```

That should print a decision document and exit 2. Try the same payload with
`--agent copilot-cli` and `--agent codex-cli` and you get the same decision in each
agent's own reply format.

Worth trying the failure cases, because they are what separate real enforcement from
theatre:

| Try this | Expect |
|---|---|
| `--policy` pointing at a file with an invalid rule | deny |
| `--policy` pointing at a file that does not exist | deny |
| no `--policy` and no policy installed | allow |
| garbage on stdin | deny |

See [ENFORCEMENT.md](ENFORCEMENT.md) for wiring it into each agent so it runs
automatically.

### 5. Telemetry

Start the collector:

```
reeve collect --store ./events.jsonl --teams examples/telemetry/teams.yaml
```

Point an agent at it with `OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318`, or
post a payload by hand to `/v1/metrics`. Both OTLP over HTTP encodings work, so no
protocol setting is needed. gRPC is not supported. Then:

```
reeve report --store ./events.jsonl --decisions /var/log/reeve/decisions.jsonl --since 168h
```

The decision log is the half no vendor can supply. An agent reports what it did; an
action the guard refused never happened as far as it is concerned.

## Two things to verify yourself

Both are properties the whole design rests on, and both are cheap to check.

**Prompt content never reaches the store.** Send the collector an event carrying prompt
text, then grep the store for it. It will not be there. A store that sometimes contains
secrets has to be treated as though it always does.

**Attribution is not taken from the client.** Send a payload asserting
`team.id: someone-elses-budget`. The report attributes it by your team mapping instead.
An agent runs on a developer's machine, so anything it says about itself is asserted
rather than proven.

## If something does not work

**`reeve` is not recognised.** Open a new terminal so the PATH change takes effect, or
run the binary by its full path.

**Commands fail after the file name in PowerShell.** They should not; flags work on
either side of the file argument. If you see it, report it.

**An agent is not detected.** Reeve looks for its configuration directory, not its
binary. If the agent is installed but has never run, there may be nothing to find.

**A config file appears to be ignored.** Reeve strips a UTF-8 byte order mark before
parsing, because Windows editors and PowerShell add one and it would otherwise make a
file parse as empty. The agents themselves may not be as forgiving, so prefer writing
config without a BOM.
