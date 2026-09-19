#!/bin/sh
#
# Runs every part of Reeve end to end against a throwaway sandbox, and checks the
# results rather than asking you to read them.
#
# Exercises all four planes in order: discovery, policy, enforcement and telemetry.
#
# Nothing here touches your real agent configuration, and nothing here reads it
# either. Four fake installations are created inside a sandbox directory, and HOME is
# pointed at the sandbox for the duration, so the results are the same on every
# machine whatever you happen to have installed. Copilot and Codex are additionally
# pointed at with COPILOT_HOME and CODEX_HOME, and Gemini's administrator files with
# GEMINI_CLI_SYSTEM_SETTINGS_PATH and GEMINI_CLI_SYSTEM_DEFAULTS_PATH.
#
# One gap worth stating rather than glossing: on Unix the administrator-owned paths
# are under /etc and have no environment override, so a machine with a real managed
# deployment there would be read. The sandbox never creates one, so the only effect
# would be an extra finding you did not put there. It is obvious when it happens.
#
# Every step asserts what should have happened. A summary at the end says whether each
# check passed, and the script exits non-zero if any did not, so it serves as a smoke
# test as well as a demonstration.
#
# The collector binds to a port the operating system picks. A fixed port is a bad
# assumption on a developer machine: 4318 is the OTLP default and is commonly already
# held by Docker, an existing collector, or something else entirely.
#
# Usage:
#   ./examples/walkthrough.sh
#   ./examples/walkthrough.sh --quiet          only the checks
#   ./examples/walkthrough.sh --keep-sandbox   leave the artifacts behind
#   ./examples/walkthrough.sh --sandbox DIR --port N

set -u

QUIET=0
KEEP_SANDBOX=0
SANDBOX="${TMPDIR:-/tmp}/reeve-walkthrough"
PORT=0

while [ $# -gt 0 ]; do
    case "$1" in
        --quiet) QUIET=1 ;;
        --keep-sandbox) KEEP_SANDBOX=1 ;;
        --sandbox) SANDBOX="$2"; shift ;;
        --port) PORT="$2"; shift ;;
        -h|--help) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
REEVE="$REPO/bin/reeve"
POLICY="$REPO/examples/policy/baseline.yaml"
TEAMS="$REPO/examples/telemetry/teams.yaml"

# ------------------------------------------------------------- helpers ----

if [ -t 1 ]; then
    GREEN=$(printf '\033[32m'); RED=$(printf '\033[31m')
    CYAN=$(printf '\033[36m'); GREY=$(printf '\033[90m'); OFF=$(printf '\033[0m')
else
    GREEN=''; RED=''; CYAN=''; GREY=''; OFF=''
fi

PASSED=0
FAILED=0
SKIPPED=0
FAILURES=""

check() {
    _name="$1"; _ok="$2"; _detail="${3:-}"
    if [ "$_ok" = "1" ]; then
        PASSED=$((PASSED + 1))
        printf '  %s[PASS]%s %s\n' "$GREEN" "$OFF" "$_name"
    else
        FAILED=$((FAILED + 1))
        FAILURES="$FAILURES
   - $_name
     $_detail"
        printf '  %s[FAIL]%s %s\n' "$RED" "$OFF" "$_name"
        [ -n "$_detail" ] && printf '         %s%s%s\n' "$RED" "$_detail" "$OFF"
    fi
}

skip() {
    SKIPPED=$((SKIPPED + 1))
    printf '  %s[SKIP]%s %s\n' "$GREY" "$OFF" "$1 ($2)"
}

step() {
    printf '\n%s%s%s\n' "$GREY" "$(rule)" "$OFF"
    printf ' %s%s. %s%s\n' "$CYAN" "$1" "$2" "$OFF"
    printf '%s%s%s\n' "$GREY" "$(rule)" "$OFF"
}

rule() { printf '=%.0s' 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 \
    26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 \
    51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74; }

note() { printf '  %s%s%s\n' "$GREY" "$1" "$OFF"; }
show() { [ "$QUIET" = "1" ] || printf '%s\n' "$1"; }

# json_get reads one value out of a JSON document.
#
# jq if it is there, python3 otherwise. With neither, the checks that need it are
# skipped and say so, rather than being silently dropped or faked with a grep that
# happens to work on today's output.
JSON_TOOL=none
command -v jq >/dev/null 2>&1 && JSON_TOOL=jq
[ "$JSON_TOOL" = none ] && command -v python3 >/dev/null 2>&1 && JSON_TOOL=python3

json_get() {
    _file="$1"; _jq="$2"; _py="$3"
    case "$JSON_TOOL" in
        jq) jq -r "$_jq" < "$_file" ;;
        python3) python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print($_py)" "$_file" ;;
    esac
}

# free_port asks the operating system for an unused one, the same way the PowerShell
# walkthrough does. Without python3 it falls back to a port nothing standard uses.
free_port() {
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
    else
        echo 47318
    fi
}

write_text() { mkdir -p "$(dirname "$1")"; cat > "$1"; }

for tool in go curl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf '%s%s is not on PATH.%s\n' "$RED" "$tool" "$OFF" >&2
        exit 1
    fi
done

# ---------------------------------------------------------------- build ----

step 0 "Build"

if ( cd "$REPO" && go build -o bin/reeve ./cmd/reeve ) 2>/tmp/reeve-build.$$; then
    check "the binary builds" 1
else
    check "the binary builds" 0 "$(cat /tmp/reeve-build.$$)"
    rm -f /tmp/reeve-build.$$
    exit 1
fi
rm -f /tmp/reeve-build.$$
show "  $("$REEVE" version)"

# -------------------------------------------------------------- sandbox ----

rm -rf "$SANDBOX"
COPILOT_SANDBOX="$SANDBOX/copilot-home"
CODEX_SANDBOX="$SANDBOX/codex-home"
GEMINI_SYSTEM="$SANDBOX/gemini-system"
PROJECT="$SANDBOX/project"

# A home directory of its own.
#
# Claude Code and Gemini have no environment variable for theirs, so without this the
# walkthrough would read whatever is installed on the machine running it and report on
# that. Two agents would be sandboxed and two would not, the counts below would depend
# on the tester, and a demo that says it touches nothing would be quietly reading real
# configuration.
SANDBOX_HOME="$SANDBOX/home"

mkdir -p "$COPILOT_SANDBOX" "$CODEX_SANDBOX" "$GEMINI_SYSTEM/policies" \
         "$PROJECT/.claude" "$SANDBOX_HOME/.claude" "$SANDBOX_HOME/.gemini/policies"

# A project whose MCP servers are defined by the repository, which is a supply-chain
# path into every machine that opens it.
write_text "$PROJECT/.mcp.json" <<'EOF'
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "fake-value-for-the-demo" }
    },
    "postgres-prod": {
      "command": "mcp-server-postgres",
      "args": ["--dsn", "postgres://reporting@db.internal:5432/payments"],
      "env": { "PGPASSWORD": "fake-value-for-the-demo" }
    }
  }
}
EOF

write_text "$PROJECT/.claude/settings.json" <<'EOF'
{
  "permissions": {
    "defaultMode": "acceptEdits",
    "allow": ["Bash(git:*)"],
    "deny": ["Read(./.env)"]
  }
}
EOF

# A Copilot install exporting prompt content.
write_text "$COPILOT_SANDBOX/settings.json" <<'EOF'
{
  "model": "auto",
  "permissions": { "deny": ["Read(**/.env)"] },
  "telemetry": { "enabled": true, "endpoint": "https://otel.corp.internal", "captureContent": true }
}
EOF

write_text "$COPILOT_SANDBOX/mcp-config.json" <<'EOF'
{
  "mcpServers": {
    "internal": {
      "type": "http",
      "url": "https://mcp.corp.internal",
      "headers": { "Authorization": "Bearer fake-value-for-the-demo" }
    }
  }
}
EOF

# A Codex install running with no sandbox and no prompting at all.
write_text "$CODEX_SANDBOX/config.toml" <<'EOF'
model = "gpt-5.6-sol"
approval_policy = "never"
sandbox_mode = "danger-full-access"

[mcp_servers.jira]
command = "mcp-jira"
env = { JIRA_API_TOKEN = "fake-value-for-the-demo" }

[otel]
exporter = "none"
EOF

# A Claude Code install, so the agent is found in the sandbox rather than on the
# machine running this.
write_text "$SANDBOX_HOME/.claude/settings.json" <<'EOF'
{
  "permissions": { "allow": ["Bash(npm run:*)"] }
}
EOF

# A Gemini install, which is the awkward one and deliberately so.
#
# An administrator wrote system-defaults.json and believes they locked auto-approval
# and turned prompt logging off. Any user setting replaces it, so it is a default
# wearing the clothes of a control.
write_text "$GEMINI_SYSTEM/system-defaults.json" <<'EOF'
{
  "security": { "disableYoloMode": true },
  "telemetry": {
    "enabled": true,
    "target": "otlp",
    "otlpEndpoint": "https://otel.corp.internal",
    "logPrompts": false
  }
}
EOF

# The developer's own file, which wins. Note what it does not say: it never asks for
# prompts to be logged. Gemini is the one supported agent that logs them unless told
# not to, so omitting the key turns capture back on, and the administrator's "false"
# went with the rest of the block it was written in.
write_text "$SANDBOX_HOME/.gemini/settings.json" <<'EOF'
{
  "security": { "disableYoloMode": false },
  "telemetry": {
    "enabled": true,
    "target": "otlp",
    "otlpEndpoint": "https://otel.corp.internal"
  },
  "mcpServers": {
    "confluence": {
      "httpUrl": "https://mcp.corp.internal/confluence",
      "headers": { "Authorization": "Bearer fake-value-for-the-demo" }
    }
  }
}
EOF

# Gemini's second configuration system, in a second format. An adapter that read only
# settings.json would describe half of this machine.
write_text "$SANDBOX_HOME/.gemini/policies/team.toml" <<'EOF'
[[rule]]
toolName = "run_shell_command"
commandPrefix = "git push"
decision = "ask_user"
priority = 10

[[rule]]
toolName = "web_fetch"
decision = "allow"
priority = 5
EOF

export COPILOT_HOME="$COPILOT_SANDBOX"
export CODEX_HOME="$CODEX_SANDBOX"
export GEMINI_CLI_SYSTEM_SETTINGS_PATH="$GEMINI_SYSTEM/settings.json"
export GEMINI_CLI_SYSTEM_DEFAULTS_PATH="$GEMINI_SYSTEM/system-defaults.json"
export HOME="$SANDBOX_HOME"

# Go resolves the home directory from USERPROFILE on Windows and from HOME
# everywhere else, so HOME alone sandboxes this script on macOS and Linux and not
# under Git Bash, where it would read the real ~/.claude and ~/.gemini and report on
# them. There is a PowerShell walkthrough for Windows, but a script that says it
# touches nothing has to be true wherever it runs, and the failure is silent: the
# findings simply describe the tester's own machine. Both are set; each is ignored
# where it means nothing.
export USERPROFILE="$SANDBOX_HOME"
export ProgramData="$SANDBOX/ProgramData"

note "sandbox at $SANDBOX"
note "home redirected to $SANDBOX_HOME for the duration"

# ------------------------------------------------------------ discovery ----

step 1 "Discovery: what is installed, and what it can actually do"
note "Reads configuration only. Never writes to an agent's files."
echo

show "$("$REEVE" scan --dir "$PROJECT" 2>&1)"

SCAN_JSON="$SANDBOX/scan.json"
"$REEVE" scan --dir "$PROJECT" --json > "$SCAN_JSON" 2>/dev/null

if [ "$JSON_TOOL" = none ]; then
    skip "four agents detected" "needs jq or python3"
    skip "findings raised against them" "needs jq or python3"
    skip "Copilot's settings were parsed, not silently skipped" "needs jq or python3"
    skip "Codex reported as running with no sandbox" "needs jq or python3"
    skip "the administrator's Gemini file is reported as overridable" "needs jq or python3"
    skip "Gemini's bypass lock reads as open" "needs jq or python3"
    skip "Gemini is capturing prompt content" "needs jq or python3"
    skip "Gemini's second configuration system was read" "needs jq or python3"
else
    AGENTS=$(json_get "$SCAN_JSON" '.installations | length' 'len(d["installations"])')
    FINDING_COUNT=$(json_get "$SCAN_JSON" '.findings | length' 'len(d["findings"])')

    [ "$AGENTS" = "4" ] && check "four agents detected" 1 || check "four agents detected" 0 "found $AGENTS"
    [ "$FINDING_COUNT" -ge 18 ] 2>/dev/null &&
        check "findings raised against them" 1 ||
        check "findings raised against them" 0 "found $FINDING_COUNT"

    # The byte order mark defect made this file read as empty, so assert it directly.
    CAPTURE=$(json_get "$SCAN_JSON" \
        '[.installations[]|select(.agent=="copilot-cli")][0].telemetry.captureContent' \
        '[i for i in d["installations"] if i["agent"]=="copilot-cli"][0]["telemetry"]["captureContent"]')
    [ "$CAPTURE" = "true" ] || [ "$CAPTURE" = "True" ] &&
        check "Copilot's settings were parsed, not silently skipped" 1 ||
        check "Copilot's settings were parsed, not silently skipped" 0 "captureContent came back as '$CAPTURE'"

    SANDBOX_MODE=$(json_get "$SCAN_JSON" \
        '[.installations[]|select(.agent=="codex-cli")][0].permissions.sandboxMode' \
        '[i for i in d["installations"] if i["agent"]=="codex-cli"][0]["permissions"]["sandboxMode"]')
    [ "$SANDBOX_MODE" = "danger-full-access" ] &&
        check "Codex reported as running with no sandbox" 1 ||
        check "Codex reported as running with no sandbox" 0 "sandboxMode was '$SANDBOX_MODE'"

    # Gemini is the agent whose failures are the quietest, so assert each directly.
    IDS=$(json_get "$SCAN_JSON" '[.findings[].id]|join(" ")' '" ".join(f["id"] for f in d["findings"])')
    case " $IDS " in
        *" policy.admin-config-is-overridable "*)
            check "the administrator's Gemini file is reported as overridable, not as a control" 1 ;;
        *)
            check "the administrator's Gemini file is reported as overridable, not as a control" 0 "findings were: $IDS" ;;
    esac

    # The proof that the file above really is only a default. The administrator set
    # disableYoloMode; the developer set it back.
    BYPASS=$(json_get "$SCAN_JSON" \
        '[.installations[]|select(.agent=="gemini-cli")][0].permissions.bypassAvailable' \
        '[i for i in d["installations"] if i["agent"]=="gemini-cli"][0]["permissions"]["bypassAvailable"]')
    [ "$BYPASS" = "true" ] || [ "$BYPASS" = "True" ] &&
        check "Gemini's bypass lock reads as open, because the developer overrode it" 1 ||
        check "Gemini's bypass lock reads as open, because the developer overrode it" 0 "bypassAvailable was '$BYPASS'"

    # The developer's telemetry block never mentions prompts. Gemini logs them unless
    # told not to, so saying nothing turns capture on.
    GCAPTURE=$(json_get "$SCAN_JSON" \
        '[.installations[]|select(.agent=="gemini-cli")][0].telemetry.captureContent' \
        '[i for i in d["installations"] if i["agent"]=="gemini-cli"][0]["telemetry"]["captureContent"]')
    [ "$GCAPTURE" = "true" ] || [ "$GCAPTURE" = "True" ] &&
        check "Gemini is capturing prompt content because the key was omitted, not set" 1 ||
        check "Gemini is capturing prompt content because the key was omitted, not set" 0 "captureContent was '$GCAPTURE'"

    # settings.json is only half of Gemini's configuration. These rules come from a
    # TOML file in a directory beside it.
    GRULES=$(json_get "$SCAN_JSON" \
        '[.installations[]|select(.agent=="gemini-cli")][0].permissions|((.ask//[])|length)+((.allow//[])|length)' \
        'len([i for i in d["installations"] if i["agent"]=="gemini-cli"][0]["permissions"].get("ask",[]))+len([i for i in d["installations"] if i["agent"]=="gemini-cli"][0]["permissions"].get("allow",[]))')
    [ "$GRULES" -ge 2 ] 2>/dev/null &&
        check "Gemini's second configuration system was read as well as its first" 1 ||
        check "Gemini's second configuration system was read as well as its first" 0 "found $GRULES rules"
fi

# --------------------------------------------------------------- policy ----

step 2 "Policy: validate it, then try it before it blocks anyone"
echo

show "$("$REEVE" policy check "$POLICY" 2>&1)"
[ $? -eq 0 ] && check "the baseline policy is valid" 1 || check "the baseline policy is valid" 0

OUT=$("$REEVE" policy test "$POLICY" --command "rm -rf /var/data" 2>&1); CODE=$?
show "$OUT"
[ "$CODE" = "2" ] && check "a destructive command is denied, exiting 2 for CI" 1 ||
    check "a destructive command is denied, exiting 2 for CI" 0 "exit was $CODE"

OUT=$("$REEVE" policy test "$POLICY" --kind read --path "services/api/.env" 2>&1); CODE=$?
show "$OUT"
[ "$CODE" = "2" ] && check "reading a credential file is denied" 1 ||
    check "reading a credential file is denied" 0 "exit was $CODE"

OUT=$("$REEVE" policy test "$POLICY" --command "go build ./..." 2>&1); CODE=$?
show "$OUT"
[ "$CODE" = "0" ] && check "an ordinary build is not blocked" 1 ||
    check "an ordinary build is not blocked" 0 "exit was $CODE"

# -------------------------------------------------------------- compile ----

step 3 "Compile: the same policy as each agent's own configuration"
note "The coverage report matters more than the files. Native configuration cannot"
note "express everything the guard can, and the compiler says so rather than quietly"
note "dropping what it cannot carry."
echo

DIST="$SANDBOX/dist"
COMPILE_OUT=$("$REEVE" policy compile "$POLICY" --out "$DIST" --platform linux 2>&1)
show "$COMPILE_OUT"

PRODUCED=$(find "$DIST" -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')
[ "$PRODUCED" = "7" ] && check "configuration produced for all five agents" 1 ||
    check "configuration produced for all five agents" 0 "wrote $PRODUCED files"

case "$COMPILE_OUT" in
    *guard-only*) check "coverage reported honestly rather than silently dropped" 1 ;;
    *) check "coverage reported honestly rather than silently dropped" 0 ;;
esac

GEMINI_POLICY=$(cat "$DIST/gemini-reeve-policy.toml" 2>/dev/null)
case "$GEMINI_POLICY" in
    *commandRegex*) check "Gemini carries substring rules the other agents cannot express" 1 ;;
    *) check "Gemini carries substring rules the other agents cannot express" 0 ;;
esac

# Gemini splices the pattern in after the literal "command":" before matching it
# against the argument JSON, which anchors it to the first character. Without a
# leading .* a rule written to catch a term anywhere catches it only at the start,
# and looks perfectly correct while doing so.
if printf '%s\n' "$GEMINI_POLICY" | grep -q 'commandRegex = "[^.]'; then
    check "each pattern is unanchored, so a term is found anywhere in a command" 0 \
        "a commandRegex does not begin with .*"
else
    check "each pattern is unanchored, so a term is found anywhere in a command" 1
fi

# Cursor's hooks fail open unless told otherwise, and that default is the whole
# reason this key is written rather than left out.
if grep -q '"failClosed": true' "$DIST/cursor-hooks.json" 2>/dev/null; then
    check "Cursor's hook is compiled to fail closed" 1
else
    check "Cursor's hook is compiled to fail closed" 0         "a hook that fails open permits the action whenever the guard crashes"
fi

if grep -q '"disableBypassPermissionsMode": *"disable"' "$DIST/claude-code-managed-settings.json" 2>/dev/null; then
    check "the bypass lock reached the compiled configuration" 1
else
    check "the bypass lock reached the compiled configuration" 0
fi

# ---------------------------------------------------------- enforcement ----

step 4 "Enforcement: the guard decides before an action happens"
note "Each payload below is the real shape that agent sends to a pre-tool hook."

DECISIONS="$SANDBOX/decisions.jsonl"

try_action() {
    _label="$1"; _agent="$2"; _payload="$3"; _want="$4"
    echo
    _out=$(printf '%s' "$_payload" | "$REEVE" guard --agent "$_agent" --policy "$POLICY" --log "$DECISIONS" 2>&1)
    _code=$?
    show "    $_out"
    [ "$_code" = "$_want" ] && check "$_label" 1 || check "$_label" 0 "exit was $_code, expected $_want"
}

try_action "Claude Code running rm -rf is denied" "claude-code" \
    '{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /important"}}' 2

try_action "Copilot CLI reading a .env file is denied" "copilot-cli" \
    '{"sessionId":"s2","hookEventName":"preToolUse","toolName":"view","toolInput":{"path":"/repo/backend/.env"}}' 2

try_action "Codex CLI running terraform apply asks the developer" "codex-cli" \
    '{"session_id":"s3","hook_event_name":"PreToolUse","tool_name":"local_shell","tool_input":{"command":"terraform apply -auto-approve"}}' 0

try_action "an ordinary build is allowed" "claude-code" \
    '{"session_id":"s4","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"npm run build"}}' 0

# Gemini names its shell tool differently, spells the event differently, and reads a
# differently named field in the reply. Each of those alone would turn a denial into
# permission, because an agent that finds no decision it recognises runs the tool.
try_action "Gemini CLI running rm -rf is denied" "gemini-cli" \
    '{"session_id":"s5","hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"cd /tmp && rm -rf /important"}}' 2

# grep_search reads files. Left to the heuristics it matches "search" and would be
# classified as a network fetch, so a rule about reading credentials would not apply.
try_action "Gemini searching inside a credential file is denied" "gemini-cli" \
    '{"session_id":"s6","hook_event_name":"BeforeTool","tool_name":"grep_search","tool_input":{"path":"/repo/backend/.env"}}' 2

# Cursor names no tool for a shell command. The kind comes from the event, and
# classifying by the absent tool name would file this as "other" and match no rule.
try_action "Cursor running rm -rf is denied, with the kind taken from the event" "cursor"     '{"hook_event_name":"beforeShellExecution","command":"cd /tmp && rm -rf /important","cwd":"/repo","sandbox":false}' 2

# Cursor hands the hook the file's entire contents. The guard writes a decision log,
# so anything it reads into the action lands on a developer's disk.
printf '%s' '{"hook_event_name":"beforeReadFile","file_path":"/repo/backend/.env","content":"AWS_SECRET=SHOULD-NEVER-BE-LOGGED","user_email":"dev@example.com"}' |
    "$REEVE" guard --agent cursor --policy "$POLICY" --log "$DECISIONS" >/dev/null 2>&1
if grep -q "SHOULD-NEVER-BE-LOGGED" "$DECISIONS" || grep -q "dev@example.com" "$DECISIONS"; then
    check "Cursor's file read is denied without the file's contents being logged" 0         "the decision log carries content or identity from Cursor's envelope"
else
    check "Cursor's file read is denied without the file's contents being logged" 1
fi


GEMINI_REPLY=$(printf '%s' '{"session_id":"s7","hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"cd /tmp && rm -rf /x"}}' |
    "$REEVE" guard --agent gemini-cli --policy "$POLICY" 2>/dev/null)
case "$GEMINI_REPLY" in
    *'"decision"'*)
        case "$GEMINI_REPLY" in
            *permissionDecision*) check "the reply is in the shape Gemini reads, not another agent's" 0 "reply was: $GEMINI_REPLY" ;;
            *) check "the reply is in the shape Gemini reads, not another agent's" 1 ;;
        esac ;;
    *) check "the reply is in the shape Gemini reads, not another agent's" 0 "reply was: $GEMINI_REPLY" ;;
esac

# A Gemini hook can only allow or deny. An ask it cannot ask is refused rather than
# waved through, because turning a rule that wanted a human decision into one that
# needs none would remove the control without reporting it.
GEMINI_ASK=$(printf '%s' '{"session_id":"s8","hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"terraform apply -auto-approve"}}' |
    "$REEVE" guard --agent gemini-cli --policy "$POLICY" 2>&1)
GEMINI_ASK_CODE=$?
case "$GEMINI_ASK" in
    *"policy engine"*)
        [ "$GEMINI_ASK_CODE" = "2" ] &&
            check "an ask Gemini cannot ask is refused rather than allowed" 1 ||
            check "an ask Gemini cannot ask is refused rather than allowed" 0 "exit was $GEMINI_ASK_CODE" ;;
    *) check "an ask Gemini cannot ask is refused rather than allowed" 0 "exit was $GEMINI_ASK_CODE" ;;
esac

step 5 "Enforcement: what happens when Reeve itself is broken"
note "This is what separates real enforcement from theatre."
echo

printf 'version: 1\nrules:\n  - id: broken\n    decision: maybe\n' > "$SANDBOX/bad.yaml"
PAYLOAD='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}'

printf '%s' "$PAYLOAD" | "$REEVE" guard --agent claude-code --policy "$SANDBOX/bad.yaml" >/dev/null 2>&1
[ $? = 2 ] && check "an unparseable policy denies, because intent is unknown" 1 ||
    check "an unparseable policy denies, because intent is unknown" 0

printf '%s' "$PAYLOAD" | "$REEVE" guard --agent claude-code --policy "$SANDBOX/missing.yaml" >/dev/null 2>&1
[ $? = 2 ] && check "a policy named but missing denies, because it is a misconfiguration" 1 ||
    check "a policy named but missing denies, because it is a misconfiguration" 0

printf '%s' "$PAYLOAD" | "$REEVE" guard --agent claude-code >/dev/null 2>&1
[ $? = 0 ] && check "no policy at all allows, because there is no intent to violate" 1 ||
    check "no policy at all allows, because there is no intent to violate" 0

printf 'this is not json' | "$REEVE" guard --agent claude-code --policy "$POLICY" >/dev/null 2>&1
[ $? = 2 ] && check "an unreadable request denies" 1 || check "an unreadable request denies" 0

# A misspelled agent is worse than a missing one: the reply would be shaped for
# nobody, and an agent that recognises nothing in it runs the tool anyway.
printf '%s' "$PAYLOAD" | "$REEVE" guard --agent gemini --policy "$POLICY" >/dev/null 2>&1
[ $? = 2 ] && check "an agent name Reeve does not know denies rather than guessing a reply shape" 1 ||
    check "an agent name Reeve does not know denies rather than guessing a reply shape" 0

# A circuit breaker, which is the only rule that matches on what already happened.
# It reads the guard's own decision log, so it is also the only one with a
# prerequisite: without a log it refuses rather than assuming nothing has happened.
LOOP_POLICY="$REPO/examples/policy/loop-breaker.yaml"
LOOP_LOG="$SANDBOX/loop-decisions.jsonl"
LOOP_PAYLOAD='{"session_id":"loop","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"curl https://api.example/retry"}}'

i=1
while [ $i -le 21 ]; do
    printf '%s' "$LOOP_PAYLOAD" |
        "$REEVE" guard --agent claude-code --policy "$LOOP_POLICY" --log "$LOOP_LOG" >/dev/null 2>&1
    LOOP_EXIT=$?
    i=$((i + 1))
done
[ "$LOOP_EXIT" = "2" ] &&
    check "a command repeated past the ceiling is stopped" 1 ||
    check "a command repeated past the ceiling is stopped" 0 "exit was $LOOP_EXIT after 21 calls"

# The same rule, with nothing to count from. An absent history is not evidence that
# nothing happened, so it must refuse rather than wave the action through.
printf '%s' "$LOOP_PAYLOAD" | "$REEVE" guard --agent claude-code --policy "$LOOP_POLICY" >/dev/null 2>&1
[ $? = 2 ] &&
    check "a counting rule with no log to count from denies, rather than assuming quiet" 1 ||
    check "a counting rule with no log to count from denies, rather than assuming quiet" 0


# ------------------------------------------------------------ telemetry ----

step 6 "Telemetry: receive what agents report, normalise it, price it"

[ "$PORT" = "0" ] && PORT=$(free_port)
note "using port $PORT (chosen by the OS, so an existing collector on 4317 or 4318 does not clash)"

EVENTS="$SANDBOX/events.jsonl"
COLLECTOR_LOG="$SANDBOX/collector.log"

"$REEVE" collect --addr "127.0.0.1:$PORT" --store "$EVENTS" --teams "$TEAMS" \
    > "$COLLECTOR_LOG" 2>&1 &
COLLECTOR_PID=$!

cleanup() {
    [ -n "${COLLECTOR_PID:-}" ] && kill "$COLLECTOR_PID" 2>/dev/null
    wait "$COLLECTOR_PID" 2>/dev/null
}
trap cleanup EXIT INT TERM

LISTENING=0
i=0
while [ $i -lt 20 ]; do
    if curl -fsS -m 2 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
        LISTENING=1
        break
    fi
    sleep 0.3 2>/dev/null || sleep 1
    i=$((i + 1))
done
[ "$LISTENING" = "1" ] && check "the collector started" 1 ||
    check "the collector started" 0 "$(cat "$COLLECTOR_LOG" 2>/dev/null)"

if [ "$LISTENING" = "1" ]; then
    post() { curl -fsS -m 5 -X POST -H 'Content-Type: application/json' --data-binary @- \
        "http://127.0.0.1:$PORT$1" >/dev/null; }

    post /v1/metrics <<'EOF'
{"resourceMetrics":[{"resource":{"attributes":[
 {"key":"service.name","value":{"stringValue":"claude-code"}},
 {"key":"user.email","value":{"stringValue":"dev@example.com"}},
 {"key":"vcs.repository.name","value":{"stringValue":"payment-service"}}]},
 "scopeMetrics":[{"metrics":[
  {"name":"claude_code.token.usage","sum":{"dataPoints":[
    {"asInt":"120000","attributes":[{"key":"type","value":{"stringValue":"input"}},{"key":"model","value":{"stringValue":"claude-sonnet-5"}}]},
    {"asInt":"18000","attributes":[{"key":"type","value":{"stringValue":"output"}},{"key":"model","value":{"stringValue":"claude-sonnet-5"}}]},
    {"asInt":"900000","attributes":[{"key":"type","value":{"stringValue":"cacheRead"}},{"key":"model","value":{"stringValue":"claude-sonnet-5"}}]}]}},
  {"name":"claude_code.cost.usage","sum":{"dataPoints":[{"asDouble":1.42,"attributes":[{"key":"model","value":{"stringValue":"claude-sonnet-5"}}]}]}},
  {"name":"claude_code.session.count","sum":{"dataPoints":[{"asInt":"1","attributes":[]}]}}]}]}]}
EOF

    post /v1/metrics <<'EOF'
{"resourceMetrics":[{"resource":{"attributes":[
 {"key":"service.name","value":{"stringValue":"copilot"}},
 {"key":"user.email","value":{"stringValue":"contractor@partner.io"}},
 {"key":"team.id","value":{"stringValue":"someone-elses-budget"}},
 {"key":"vcs.repository.name","value":{"stringValue":"billing-api"}}]},
 "scopeMetrics":[{"metrics":[
  {"name":"gen_ai.client.token.usage","sum":{"dataPoints":[
    {"asInt":"45000","attributes":[{"key":"gen_ai.token.type","value":{"stringValue":"input"}},{"key":"gen_ai.request.model","value":{"stringValue":"gpt-5.6-sol"}}]},
    {"asInt":"9000","attributes":[{"key":"gen_ai.token.type","value":{"stringValue":"output"}},{"key":"gen_ai.request.model","value":{"stringValue":"gpt-5.6-sol"}}]}]}}]}]}]}
EOF

    post /v1/logs <<'EOF'
{"resourceLogs":[{"resource":{"attributes":[
 {"key":"service.name","value":{"stringValue":"codex"}},
 {"key":"user.email","value":{"stringValue":"dev2@example.com"}}]},
 "scopeLogs":[{"logRecords":[
  {"attributes":[{"key":"event.name","value":{"stringValue":"codex.api_request"}},
    {"key":"input_tokens","value":{"intValue":"30000"}},
    {"key":"output_tokens","value":{"intValue":"4000"}},
    {"key":"model","value":{"stringValue":"gpt-5.6-sol"}}]},
  {"attributes":[{"key":"event.name","value":{"stringValue":"codex.user_prompt"}},
    {"key":"prompt","value":{"stringValue":"SECRET-THIS-MUST-NEVER-BE-STORED"}}]}]}]}]}
EOF

    post /v1/metrics <<'EOF'
{"resourceMetrics":[{"resource":{"attributes":[
 {"key":"service.name","value":{"stringValue":"gemini-cli"}},
 {"key":"user.email","value":{"stringValue":"dev3@example.com"}},
 {"key":"vcs.repository.name","value":{"stringValue":"payment-service"}}]},
 "scopeMetrics":[{"metrics":[
  {"name":"gemini_cli.token.usage","sum":{"dataPoints":[
    {"asInt":"50000","attributes":[{"key":"type","value":{"stringValue":"input"}},{"key":"model","value":{"stringValue":"gemini-3-pro"}}]},
    {"asInt":"7000","attributes":[{"key":"type","value":{"stringValue":"output"}},{"key":"model","value":{"stringValue":"gemini-3-pro"}}]}]}}]}]}]}
EOF

    STATS=$(curl -fsS "http://127.0.0.1:$PORT/stats")
    note "stats: $STATS"
    case "$STATS" in
        *'"batchesReceived":4'*) check "all four agents' telemetry was accepted" 1 ;;
        *) check "all four agents' telemetry was accepted" 0 "$STATS" ;;
    esac

    WRITTEN=$(printf '%s' "$STATS" | sed 's/.*"eventsWritten":\([0-9]*\).*/\1/')
    [ "$WRITTEN" -ge 10 ] 2>/dev/null &&
        check "events were normalised and stored" 1 ||
        check "events were normalised and stored" 0 "wrote $WRITTEN"
fi

cleanup
COLLECTOR_PID=

step 7 "Two properties the whole design rests on"
echo

if [ -f "$EVENTS" ]; then
    if grep -q "SECRET-THIS-MUST-NEVER-BE-STORED" "$EVENTS"; then
        check "a prompt was sent, but its text is not in the store" 0
    else
        check "a prompt was sent, but its text is not in the store" 1
    fi
    if grep -q "someone-elses-budget" "$EVENTS"; then
        check "a client-asserted team was ignored" 0
    else
        check "a client-asserted team was ignored" 1
    fi
    if grep -q "platform" "$EVENTS" && grep -q "integrations" "$EVENTS"; then
        check "attribution resolved from your mapping instead" 1
    else
        check "attribution resolved from your mapping instead" 0
    fi
else
    check "the event store exists" 0 "no file at $EVENTS"
fi

# --------------------------------------------------------------- report ----

step 8 "The report: cost and policy across every agent at once"
echo

if [ -f "$EVENTS" ]; then
    REPORT=$("$REEVE" report --store "$EVENTS" --decisions "$DECISIONS" --top 5 2>&1)
    printf '%s\n' "$REPORT"

    case "$REPORT" in
        *"estimated from tokens"*) check "cost computed from tokens across four vendors" 1 ;;
        *) check "cost computed from tokens across four vendors" 0 ;;
    esac
    case "$REPORT" in
        *"vendor cost"*) check "the vendors' own figure shown separately, not merged" 1 ;;
        *) check "the vendors' own figure shown separately, not merged" 0 ;;
    esac
    case "$REPORT" in
        *"By team"*) check "spend attributed by team" 1 ;;
        *) check "spend attributed by team" 0 ;;
    esac
    case "$REPORT" in
        *blocked*) check "refusals appear, which no vendor telemetry can report" 1 ;;
        *) check "refusals appear, which no vendor telemetry can report" 0 ;;
    esac
fi

# ------------------------------------------------------------- posture ----

step 9 "Fleet posture: the same question asked about every machine at once"
note "Reads files. No listener, no agent, no machine reporting on its own behalf."
echo

FLEET="$SANDBOX/fleet"
mkdir -p "$FLEET/eu-west" "$FLEET/us-east"

# Three scans of this machine, which carry its hostname, plus one that does not.
# Two machines, from four reports.
"$REEVE" scan --dir "$PROJECT" --json --include-hostname > "$FLEET/eu-west/monday.json" 2>/dev/null
cp "$FLEET/eu-west/monday.json" "$FLEET/eu-west/tuesday.json"
cp "$FLEET/eu-west/monday.json" "$FLEET/us-east/wednesday.json"
cp "$SCAN_JSON" "$FLEET/us-east/anonymous.json"

# An upload that was cut off partway. The machine it came from is exactly the kind
# most likely to be in a state nobody has looked at.
printf '{"schemaVersion":' > "$FLEET/us-east/interrupted.json"

POSTURE=$("$REEVE" posture "$FLEET" --top 4 2>&1)
show "$POSTURE"

case "$POSTURE" in
    *"machines          : 2"*)
        check "three scans of one machine count as one machine" 1 ;;
    *)  check "three scans of one machine count as one machine" 0             "a fleet that rescans nightly would report every number several times over" ;;
esac

case "$POSTURE" in
    *"could not be read"*)
        check "the report that arrived truncated is named, not quietly dropped" 1 ;;
    *)  check "the report that arrived truncated is named, not quietly dropped" 0             "the machines whose scans fail are not a random sample of the fleet" ;;
esac

case "$POSTURE" in
    *"carry no hostname"*)
        check "the count says so when it cannot tell two machines apart" 1 ;;
    *)  check "the count says so when it cannot tell two machines apart" 0 ;;
esac

# Percentages are of the machines running that agent. Of the fleet, a total failure
# confined to one uncommon agent reads as a rounding error and never gets looked at.
case "$POSTURE" in
    *"of 2 machines with"*)
        check "a finding is measured against the machines that run that agent" 1 ;;
    *)  check "a finding is measured against the machines that run that agent" 0 ;;
esac

"$REEVE" posture "$FLEET" --fail-on high >/dev/null 2>&1
[ $? = 2 ] &&
    check "the gate fails while part of the fleet could not be read" 1 ||
    check "the gate fails while part of the fleet could not be read" 0         "passing on the machines that did report is a verdict on the wrong population"

# Any JSON object decodes into a report with every field empty, and a report with no
# agents and no findings is what a perfectly governed machine looks like.
mkdir -p "$SANDBOX/not-reports"
printf '{"name":"app","version":"1.0.0"}' > "$SANDBOX/not-reports/package.json"
WRONG=$("$REEVE" posture "$SANDBOX/not-reports" 2>&1)
[ $? != 0 ] &&
    check "the wrong directory is an error rather than a clean bill of health" 1 ||
    check "the wrong directory is an error rather than a clean bill of health" 0         "reported: $WRONG"

# -------------------------------------------------------------- summary ----

echo
printf '%s%s%s\n' "$GREY" "$(rule)" "$OFF"
if [ "$FAILED" = "0" ]; then
    if [ "$SKIPPED" = "0" ]; then
        printf ' %sAll %s checks passed.%s\n' "$GREEN" "$PASSED" "$OFF"
    else
        printf ' %s%s checks passed, %s skipped.%s\n' "$GREEN" "$PASSED" "$SKIPPED" "$OFF"
    fi
else
    printf ' %s%s passed, %s FAILED.%s\n%s\n' "$RED" "$PASSED" "$FAILED" "$OFF" "$FAILURES"
fi
printf '%s%s%s\n' "$GREY" "$(rule)" "$OFF"

echo
note "Artifacts:"
note "  events    $EVENTS"
note "  decisions $DECISIONS"
note "  compiled  $DIST"
[ "$KEEP_SANDBOX" = "1" ] || note "Remove with: rm -rf '$SANDBOX'"

[ "$FAILED" = "0" ] || exit 1
