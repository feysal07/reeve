# Adding an agent

Reeve covers an agent through four surfaces, and a new agent touches all of them. Nothing
here is a stable public interface yet: these are internal packages, and they will change
until a second adapter has been written outside this repository. Read this as a map of
what to change, not as an API promise.

| Surface | Package | What it answers |
|---|---|---|
| Scan | `internal/adapter` | What is installed, how it is configured, which MCP servers it runs. |
| Hook | `internal/hook` | What the agent is about to do, as a `policy.Action`, and how to tell it the answer. |
| Compile | `internal/compile` | The policy as the agent's own administrator-owned configuration. |
| Install | `internal/install` | Registering the guard as the agent's hook, and taking it out again. |

Every surface fails the same way when it is wrong: it looks like success. A scan that
cannot parse a file and reports it empty, a hook reply in another agent's spelling that the
agent reads as no decision, a compiled rule stripped of a condition and reported native, an
installer that takes a developer's own hook for the guard. Each section below names the
one that bit, and the check that now stands in its way.

## Scan: `internal/adapter`

An adapter implements `adapter.Adapter`: `ID`, `DisplayName`, a cheap `Detect`, and
`Inspect`, which reads the configuration into a `model.Installation`. A file that exists and
cannot be read is recorded with its `ParseError`, never read as an empty file; returning an
error instead drops the whole installation from the scan. This is the whole of a minimal adapter,
compiled and tested with the rest of the code (`internal/adapter/example/example.go`):

```go
// Package example is the adapter docs/ADAPTERS.md walks through: the smallest scan adapter
// that is honest about what it read. It is compiled and tested with everything else, and
// the guide quotes this file, so the example cannot drift from the interface.
package example

import (
	"context"
	"os"
	"path/filepath"

	"github.com/feysal07/reeve/internal/adapter"
	"github.com/feysal07/reeve/internal/config"
	"github.com/feysal07/reeve/internal/model"
)

// Adapter reads an imaginary agent that keeps its settings in ~/.example/settings.json.
type Adapter struct{}

// ID is the agent's id, as policy rules and the decision log name it.
func (Adapter) ID() model.AgentID { return "example-agent" }

// DisplayName is the vendor's own name for the product.
func (Adapter) DisplayName() string { return "Example Agent" }

// Detect is cheap: is the agent's configuration directory there at all?
func (Adapter) Detect(_ context.Context, env adapter.Env) (bool, error) {
	_, err := os.Stat(filepath.Join(env.Home, ".example"))
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

// Inspect reads the configuration. A file that exists and cannot be parsed is recorded as
// such on the installation, never read as a file with nothing in it: one stray comment
// once made scan report no deny rules on a machine that had two. Recorded rather than
// returned as an error, because an error drops the whole installation from the scan, and
// the agent is still there with a file somebody needs to fix.
func (a Adapter) Inspect(_ context.Context, env adapter.Env) (model.Installation, error) {
	inst := model.Installation{Agent: a.ID(), DisplayName: a.DisplayName()}
	path := filepath.Join(env.Home, ".example", "settings.json")
	var settings struct {
		Deny []string `json:"deny"`
	}
	doc := config.ReadJSON(path, &settings)
	file := model.ConfigFile{Path: path, Scope: model.ScopeUser, Exists: doc.Found}
	if doc.Err != nil {
		file.ParseError = doc.Err.Error()
	}
	inst.ConfigFiles = append(inst.ConfigFiles, file)
	for _, raw := range settings.Deny {
		inst.Permissions.Deny = append(inst.Permissions.Deny, model.Rule{Raw: raw, Scope: model.ScopeUser})
	}
	return inst, nil
}
```

Optional interfaces add what scan and the guard can do with the agent:

- `adapter.MCPLister` lists configured MCP servers without a full `Inspect`.
- `adapter.ProjectMCP` names the MCP servers one project's own configuration defines, so a
  server called by a name that looks like a desktop built-in or a connector can be told
  from a project's server of the same name.
- `adapter.StrictMCP` lists every server the agent would start for a directory, failing on
  a file it cannot read, so the guard identifies a called server by what it runs.

Register the adapter in `supportedAdapters()` in `cmd/reeve`, and add the agent to
`model.AllAgents()` and `model.HasAdapter`. `model.ReadsVersion` says whether scan reads the installed version; a
minimum version in policy reports every install as unknown until it does.

## Hook: `internal/hook`

`hook.Decode` turns the agent's pre-tool request into a `policy.Action`, and `hook.Encode`
turns the decision into the reply the agent reads. The fields a rule can match on, which a
new agent's request must fill where it can:

| Field | What it carries |
|---|---|
| `Agent`, `Event`, `SessionID`, `CWD`, `ToolName`, `ToolUseID` | Who is asking, about which tool call, from where. |
| `Kind` | The neutral kind: shell, read, write, fetch, mcp. |
| `Command`, `Paths`, `URLs` | What the action runs, touches or reaches. |
| `MCPServer`, `MCPTool`, `MCPArguments` | An MCP call; arguments are matched, never logged. |
| `EditContent` | What a write puts in place; matched, never logged. |
| `Prompt` | The prompt, where the event carries one; never stored. |
| `MCPStanding` | Where the MCP server stands against the approved list; resolved by the guard. |
| `Repository` | The repository and branch an action reaches; resolved by the guard from `.git`. |
| `Environment`, `EnvironmentDetail` | The environment a command or MCP call reaches; resolved by the guard. |
| `History`, `Spend`, `Allowance`, `Identity`, `At` | What came before, what was spent, the plan, who is asking, and when; resolved by the guard. |

The fields the guard resolves arrive empty from the hook and are filled before the policy
is evaluated; a rule that needs one the guard could not resolve refuses.

Teach the hook the agent in three places in `internal/hook`: its request shape in `Decode`,
its reply in the `Encode` switch, and `supportedAgents`, which `reeve guard --agent` accepts.
Then give it a conformance entry in `conformance.go`: the request shape, captured from a
real installation where possible, and how the agent reads a reply. Then run the kit:

```go
c, ok := hook.ConformanceFor("example-agent")
if !ok {
	t.Fatal("no conformance entry")
}
if err := hook.CheckEncoder(c, hook.Encode); err != nil {
	t.Fatal(err)
}
```

`CheckEncoder` decodes the agent's own request for its event, encodes a deny, an ask and an
allow, and fails an encoder whose refusal or ask the agent would take as permission, or
whose reply exits anything but 0 or 2, which agents read as a failed hook. That is the
failure doctor's probe was rewritten for: a reply in another agent's spelling parses
perfectly, carries no decision the agent recognises, and the agent runs the tool.

## Compile: `internal/compile`

A compiler implements `compile.Compiler`, is added to `compile.All()`, and reports, for every rule, whether the agent's
own configuration enforces it: native, partial, guard-only, unenforceable, observe or
not-applicable. Every compiler first asks `forOtherAgents` and `conditionalCoverage`: a rule
for another agent is not this one's, and a rule on something only the guard can see, a
count, a budget, an environment, a repository, an MCP server's standing, a commit message
or an edit's content, is guard-only and emits nothing. A test fails the day a field is
added to the policy match without a decision about whether compilers can express it.

## Install: `internal/install`

An installer implements the package's `agentInstaller` and is added to `installers()`. It
registers the guard as the agent's hook and removes only what it added. A hook
is the guard's by its shape, a program, then `guard`, then `--agent`, and a reeve binary or
the `--policy` or `--log` it always passes, never by a substring: a developer's own hook
under a directory called `reeve-guard` was once taken for the guard, replaced, deleted and
run. Test every installer against a sandboxed home, never a real one.
