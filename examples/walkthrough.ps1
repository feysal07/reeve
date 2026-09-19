<#
.SYNOPSIS
    Runs every part of Reeve end to end against a throwaway sandbox, and checks the
    results rather than asking you to read them.

.DESCRIPTION
    Exercises all four planes in order: discovery, policy, enforcement and telemetry.

    Nothing here touches your real agent configuration, and nothing here reads it
    either. Four fake installations are created inside a sandbox directory, and the
    home directory is pointed at the sandbox for the duration, so the results are the
    same on every machine whatever you happen to have installed. Copilot and Codex
    are additionally pointed at with COPILOT_HOME and CODEX_HOME, and Gemini's
    administrator files with GEMINI_CLI_SYSTEM_SETTINGS_PATH and
    GEMINI_CLI_SYSTEM_DEFAULTS_PATH, which each agent honours.

    Every step asserts what should have happened. A summary at the end says whether
    each check passed, and the script exits non-zero if any did not, so it serves as a
    smoke test as well as a demonstration.

    The collector binds to a port the operating system picks. A fixed port is a bad
    assumption on a developer machine: 4318 is the OTLP default and is commonly
    already held by Docker Desktop, WSL, or an existing collector.

.EXAMPLE
    .\examples\walkthrough.ps1

.EXAMPLE
    .\examples\walkthrough.ps1 -Quiet
    Only the checks, without the full output of each command.

.EXAMPLE
    .\examples\walkthrough.ps1 -KeepSandbox -Sandbox C:\temp\reeve-demo
#>
[CmdletBinding()]
param(
    [string]$Sandbox = (Join-Path $env:TEMP "reeve-walkthrough"),
    [switch]$KeepSandbox,
    [switch]$Quiet,
    [int]$Port = 0
)

# Native commands here write explanations to stderr as a normal part of their job: the
# guard puts the reason a developer was blocked there. Windows PowerShell turns any
# native stderr into a terminating error when ErrorActionPreference is Stop, which
# would abort the walkthrough on its first successful denial.
$ErrorActionPreference = "Continue"

# PowerShell encodes what it pipes into a native command. Without this a payload can
# arrive with a byte order mark or in the wrong code page.
$OutputEncoding = New-Object System.Text.UTF8Encoding $false

$repo = Split-Path -Parent $PSScriptRoot
$reeve = Join-Path $repo "bin\reeve.exe"
$policy = Join-Path $repo "examples\policy\baseline.yaml"
$teams = Join-Path $repo "examples\telemetry\teams.yaml"

# ------------------------------------------------------------- helpers ----

$script:checks = @()

function Check($name, [bool]$ok, $detail = "") {
    $script:checks += [PSCustomObject]@{ Name = $name; Ok = $ok; Detail = $detail }
    if ($ok) {
        Write-Host "  [PASS] $name" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $name" -ForegroundColor Red
        if ($detail) { Write-Host "         $detail" -ForegroundColor Red }
    }
}

function Step($n, $title) {
    Write-Host ""
    Write-Host ("=" * 74) -ForegroundColor DarkGray
    Write-Host " $n. $title" -ForegroundColor Cyan
    Write-Host ("=" * 74) -ForegroundColor DarkGray
}

function Note($text) { Write-Host "  $text" -ForegroundColor DarkGray }
function Show($text) { if (-not $Quiet) { Write-Host $text } }

# Write-Text writes UTF-8 with no byte order mark. Set-Content -Encoding utf8 on
# Windows PowerShell 5.1 adds one, and a BOM in a config file is a real hazard: Reeve
# strips it when reading, but the agents themselves may not.
function Write-Text($path, $content) {
    [System.IO.File]::WriteAllText($path, $content, (New-Object System.Text.UTF8Encoding $false))
}

# Find-FreePort asks the operating system for an unused port.
function Find-FreePort {
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $p = $listener.LocalEndpoint.Port
    $listener.Stop()
    return $p
}

# ---------------------------------------------------------------- build ----

Step 0 "Build"

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Host "  Go is not on PATH." -ForegroundColor Red
    Write-Host "  Open a new terminal, or add C:\Users\$env:USERNAME\tools\go\bin to PATH." -ForegroundColor Red
    exit 1
}

Push-Location $repo
try {
    $buildOutput = & go build -o bin\reeve.exe .\cmd\reeve 2>&1
    $buildOk = ($LASTEXITCODE -eq 0)
} finally {
    Pop-Location
}
Check "the binary builds" $buildOk ($buildOutput | Out-String)
if (-not $buildOk) { exit 1 }
Show ("  " + (& $reeve version))

# -------------------------------------------------------------- sandbox ----

if (Test-Path $Sandbox) { Remove-Item -Recurse -Force $Sandbox }
$copilotHome = Join-Path $Sandbox "copilot-home"
$codexHome = Join-Path $Sandbox "codex-home"
$geminiSystem = Join-Path $Sandbox "gemini-system"
$project = Join-Path $Sandbox "project"

# A home directory of its own.
#
# Claude Code and Gemini have no environment variable for theirs, so without this the
# walkthrough would read whatever is installed on the machine running it and report on
# that. Two agents would be sandboxed and two would not, the counts below would depend
# on the tester, and a demo that says it touches nothing would be quietly reading real
# configuration.
$sandboxHome = Join-Path $Sandbox "home"

New-Item -ItemType Directory -Force -Path `
    $Sandbox, $copilotHome, $codexHome, $geminiSystem, $project, $sandboxHome | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $project ".claude") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $sandboxHome ".claude") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $sandboxHome ".gemini\policies") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $geminiSystem "policies") | Out-Null

# A project whose MCP servers are defined by the repository, which is a supply-chain
# path into every machine that opens it.
Write-Text (Join-Path $project ".mcp.json") @'
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
'@

Write-Text (Join-Path $project ".claude\settings.json") @'
{
  "permissions": {
    "defaultMode": "acceptEdits",
    "allow": ["Bash(git:*)"],
    "deny": ["Read(./.env)"]
  }
}
'@

# A Copilot install exporting prompt content.
Write-Text (Join-Path $copilotHome "settings.json") @'
{
  "model": "auto",
  "permissions": { "deny": ["Read(**/.env)"] },
  "telemetry": { "enabled": true, "endpoint": "https://otel.corp.internal", "captureContent": true }
}
'@

Write-Text (Join-Path $copilotHome "mcp-config.json") @'
{
  "mcpServers": {
    "internal": {
      "type": "http",
      "url": "https://mcp.corp.internal",
      "headers": { "Authorization": "Bearer fake-value-for-the-demo" }
    }
  }
}
'@

# A Codex install running with no sandbox and no prompting at all.
Write-Text (Join-Path $codexHome "config.toml") @'
model = "gpt-5.6-sol"
approval_policy = "never"
sandbox_mode = "danger-full-access"

[mcp_servers.jira]
command = "mcp-jira"
env = { JIRA_API_TOKEN = "fake-value-for-the-demo" }

[otel]
exporter = "none"
'@

# A Claude Code install, so the agent is found in the sandbox rather than on the
# machine running this.
Write-Text (Join-Path $sandboxHome ".claude\settings.json") @'
{
  "permissions": { "allow": ["Bash(npm run:*)"] }
}
'@

# A Gemini install, which is the awkward one and deliberately so.
#
# An administrator wrote system-defaults.json and believes they locked auto-approval
# and turned prompt logging off. Any user setting replaces it, so it is a default
# wearing the clothes of a control.
Write-Text (Join-Path $geminiSystem "system-defaults.json") @'
{
  "security": { "disableYoloMode": true },
  "telemetry": {
    "enabled": true,
    "target": "otlp",
    "otlpEndpoint": "https://otel.corp.internal",
    "logPrompts": false
  }
}
'@

# The developer's own file, which wins. Note what it does not say: it never asks for
# prompts to be logged. Gemini is the one supported agent that logs them unless told
# not to, so omitting the key turns capture back on, and the administrator's "false"
# went with the rest of the block it was written in.
Write-Text (Join-Path $sandboxHome ".gemini\settings.json") @'
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
'@

# Gemini's second configuration system, in a second format. An adapter that read only
# settings.json would describe half of this machine.
Write-Text (Join-Path $sandboxHome ".gemini\policies\team.toml") @'
[[rule]]
toolName = "run_shell_command"
commandPrefix = "git push"
decision = "ask_user"
priority = 10

[[rule]]
toolName = "web_fetch"
decision = "allow"
priority = 5
'@

$env:COPILOT_HOME = $copilotHome
$env:CODEX_HOME = $codexHome
$env:GEMINI_CLI_SYSTEM_SETTINGS_PATH = Join-Path $geminiSystem "settings.json"
$env:GEMINI_CLI_SYSTEM_DEFAULTS_PATH = Join-Path $geminiSystem "system-defaults.json"

# The administrator-owned half of the same problem. Every agent's managed file lives
# under ProgramData on Windows, and for Cursor that is the only administrator-owned
# file it has. Left pointing at the real one, a machine with a genuine managed
# deployment would report an extra agent, or a control the sandbox never created.
$managedRoot = Join-Path $Sandbox "ProgramData"
New-Item -ItemType Directory -Force -Path $managedRoot | Out-Null

# Saved so they can be put back, in case this is run in an existing session rather
# than as a script.
$realUserProfile = $env:USERPROFILE
$realHome = $env:HOME
$realProgramData = $env:ProgramData
$env:USERPROFILE = $sandboxHome
$env:HOME = $sandboxHome
$env:ProgramData = $managedRoot

Note "sandbox at $Sandbox"
Note "home redirected to $sandboxHome, ProgramData to $managedRoot, for the duration"

# ------------------------------------------------------------ discovery ----

Step 1 "Discovery: what is installed, and what it can actually do"
Note "Reads configuration only. Never writes to an agent's files."
Write-Host ""

Show (& $reeve scan --dir $project 2>&1 | Out-String)

$scanJson = (& $reeve scan --dir $project --json 2>&1 | Out-String) | ConvertFrom-Json
$agents = @($scanJson.installations).Count
$findings = @($scanJson.findings).Count

Check "four agents detected" ($agents -eq 4) "found $agents"
Check "findings raised against them" ($findings -ge 18) "found $findings"

# The byte order mark defect made this file read as empty, so assert it directly.
$copilotInst = $scanJson.installations | Where-Object { $_.agent -eq "copilot-cli" }
Check "Copilot's settings were parsed, not silently skipped" `
    ($copilotInst.telemetry.captureContent -eq $true) `
    "captureContent came back as '$($copilotInst.telemetry.captureContent)'"

$codexInst = $scanJson.installations | Where-Object { $_.agent -eq "codex-cli" }
Check "Codex reported as running with no sandbox" `
    ($codexInst.permissions.sandboxMode -eq "danger-full-access") `
    "sandboxMode was '$($codexInst.permissions.sandboxMode)'"

# Gemini is the agent whose failures are the quietest, so assert each one directly.
$geminiInst = $scanJson.installations | Where-Object { $_.agent -eq "gemini-cli" }
$findingIds = @($scanJson.findings | ForEach-Object { $_.id })

Check "the administrator's Gemini file is reported as overridable, not as a control" `
    ($findingIds -contains "policy.admin-config-is-overridable") `
    "findings were: $($findingIds -join ', ')"

# The proof that the file above really is only a default. The administrator set
# disableYoloMode; the developer set it back. A scan that only ever reported locks
# closing would describe a machine where bypass was unavailable, and the finding
# about it would never fire.
Check "Gemini's bypass lock reads as open, because the developer overrode it" `
    ($geminiInst.permissions.bypassAvailable -eq $true) `
    "bypassAvailable came back as '$($geminiInst.permissions.bypassAvailable)'"

# The developer's telemetry block never mentions prompts. Gemini logs them unless
# told not to, so saying nothing turns capture on and takes the administrator's
# "false" with it.
Check "Gemini is capturing prompt content because the key was omitted, not set" `
    ($geminiInst.telemetry.captureContent -eq $true) `
    "captureContent came back as '$($geminiInst.telemetry.captureContent)'"

# settings.json is only half of Gemini's configuration. These rules come from a TOML
# file in a directory beside it.
$geminiRules = @($geminiInst.permissions.ask).Count + @($geminiInst.permissions.allow).Count
Check "Gemini's second configuration system was read as well as its first" `
    ($geminiRules -ge 2) "found $geminiRules rules from the policy engine"


# A file that cannot be read must never read as a file with nothing in it.
#
# Its own sandbox home, because these checks deliberately break a settings file and
# every other check in this script depends on the main one being intact.
$readHome = Join-Path $Sandbox "readability"
New-Item -ItemType Directory -Force -Path (Join-Path $readHome ".claude") | Out-Null
$readSettings = Join-Path $readHome ".claude\settings.json"

# Comments are routine in these files: several of these agents come from editor
# lineages where configuration is JSONC, and whoever writes a deny rule is the same
# person who writes a line above it saying why.
Write-Text $readSettings @'
{
  // Block the obvious foot-guns. Reviewed 2026-09-01.
  "permissions": {
    "deny": ["Read(**/.env)", "Bash(rm -rf:*)"],
    "allowRules": ["a key this build has never heard of"]
  }
}
'@

$savedProfile2 = $env:USERPROFILE
$savedHome2 = $env:HOME
$env:USERPROFILE = $readHome
$env:HOME = $readHome
try {
    $readScan = (& $reeve scan --dir $readHome --json 2>$null | Out-String) | ConvertFrom-Json
    $cc = $readScan.installations | Where-Object { $_.agent -eq "claude-code" }

    Check "a comment does not delete every rule in the file" `
        (@($cc.permissions.deny).Count -eq 2) `
        "found $(@($cc.permissions.deny).Count) deny rules; a commented file used to read as an empty one"

    $unknown = @($cc.configFiles | ForEach-Object { $_.unknownKeys } | Where-Object { $_ })
    Check "settings this build does not understand are reported" `
        ($unknown.Count -ge 1) `
        "found $($unknown.Count); a renamed vendor key would go unnoticed"

    # Now break it outright. An unparseable file and an empty one produce the same
    # empty result, and only one of them means the machine has no rules.
    Set-Content -Path $readSettings -Value '{"permissions": {"deny": ["Read(**/.env)"' -Encoding utf8
    $brokenOut = (& $reeve scan --dir $readHome 2>&1 | Out-String)
    Check "a file that cannot be read is not reported as a file with nothing in it" `
        ($brokenOut -match "could not be read") `
        "the scan reported a clean machine"
} finally {
    $env:USERPROFILE = $savedProfile2
    if ($savedHome2) { $env:HOME = $savedHome2 } else { Remove-Item Env:\HOME -ErrorAction SilentlyContinue }
}

# The capture is meant to be sent to a stranger, so the one property that matters
# is that no value from the file survives into it.
$captureDir = Join-Path $Sandbox "captured"
& $reeve scan --dir $project --capture $captureDir > $null 2>&1
$capturedFiles = @(Get-ChildItem $captureDir -File -ErrorAction SilentlyContinue)
if ($capturedFiles.Count -gt 0) {
    $blob = ($capturedFiles | ForEach-Object { Get-Content $_.FullName -Raw }) -join "`n"
    $leaked = @()
    foreach ($secret in @("fake-value-for-the-demo", "postgres://reporting@db.internal",
                          "https://otel.corp.internal", "danger-full-access")) {
        if ($blob.Contains($secret)) { $leaked += $secret }
    }
    Check "a captured configuration sample contains no value from the file" `
        ($leaked.Count -eq 0) "leaked: $($leaked -join ', ')"

    # And it has to keep the keys, or it is not a sample of anything.
    Check "a captured sample keeps the keys, which are the point of it" `
        ($blob.Contains("mcpServers")) "no keys survived"
} else {
    Check "a captured configuration sample contains no value from the file" $false "nothing was captured"
    Check "a captured sample keeps the keys, which are the point of it" $false "nothing was captured"
}

# --------------------------------------------------------------- policy ----

Step 2 "Policy: validate it, then try it before it blocks anyone"
Write-Host ""

Show (& $reeve policy check $policy 2>&1 | Out-String)
Check "the baseline policy is valid" ($LASTEXITCODE -eq 0)

Show (& $reeve policy test $policy --command "rm -rf /var/data" 2>&1 | Out-String)
Check "a destructive command is denied, exiting 2 for CI" ($LASTEXITCODE -eq 2) "exit was $LASTEXITCODE"

Show (& $reeve policy test $policy --kind read --path "services/api/.env" 2>&1 | Out-String)
Check "reading a credential file is denied" ($LASTEXITCODE -eq 2) "exit was $LASTEXITCODE"

Show (& $reeve policy test $policy --command "go build ./..." 2>&1 | Out-String)
Check "an ordinary build is not blocked" ($LASTEXITCODE -eq 0) "exit was $LASTEXITCODE"

# -------------------------------------------------------------- compile ----

Step 3 "Compile: the same policy as each agent's own configuration"
Note "The coverage report matters more than the files. Native configuration cannot"
Note "express everything the guard can, and the compiler says so rather than quietly"
Note "dropping what it cannot carry."
Write-Host ""

$dist = Join-Path $Sandbox "dist"
$compileText = (& $reeve policy compile $policy --out $dist --platform linux 2>&1 | Out-String)
Show $compileText

$produced = @(Get-ChildItem $dist -ErrorAction SilentlyContinue)
Check "configuration produced for all five agents" ($produced.Count -eq 7) "wrote $($produced.Count) files"
Check "coverage reported honestly rather than silently dropped" ($compileText -match "guard-only")

# Gemini's policy engine takes a regex, so rules the others can only hand to the
# guard survive translation. The anchoring below is the whole reason that works.
$geminiPolicy = Get-Content (Join-Path $dist "gemini-reeve-policy.toml") -Raw
Check "Gemini carries substring rules the other agents cannot express" `
    ($geminiPolicy -match "commandRegex")

# Gemini splices the pattern in after the literal "command":" before matching it
# against the argument JSON, which anchors it to the first character. Without a
# leading .* a rule written to catch a term anywhere catches it only at the start,
# and looks perfectly correct while doing so.
Check "each pattern is unanchored, so a term is found anywhere in a command" `
    (-not ($geminiPolicy -match 'commandRegex = "(?!\.\*)')) `
    "a commandRegex does not begin with .*"

$claudeCfg = Get-Content (Join-Path $dist "claude-code-managed-settings.json") -Raw | ConvertFrom-Json
# Cursor's hooks fail open unless told otherwise, and that default is the whole
# reason this key is written rather than left out.
$cursorHooks = Get-Content (Join-Path $dist "cursor-hooks.json") -Raw
Check "Cursor's hook is compiled to fail closed" `
    ($cursorHooks -match '"failClosed": true') `
    "a hook that fails open permits the action whenever the guard crashes"

Check "the bypass lock reached the compiled configuration" `
    ($claudeCfg.permissions.disableBypassPermissionsMode -eq "disable")

# ---------------------------------------------------------- enforcement ----

Step 4 "Enforcement: the guard decides before an action happens"
Note "Each payload below is the real shape that agent sends to a pre-tool hook."

$decisions = Join-Path $Sandbox "decisions.jsonl"

function Try-Action($label, $agent, $payload, $wantExit) {
    Write-Host ""
    $out = ($payload | & $reeve guard --agent $agent --policy $policy --log $decisions 2>&1 | Out-String)
    $code = $LASTEXITCODE
    Show ("    " + $out.Trim())
    Check $label ($code -eq $wantExit) "exit was $code, expected $wantExit"
}

Try-Action "Claude Code running rm -rf is denied" "claude-code" `
    '{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /important"}}' 2

Try-Action "Copilot CLI reading a .env file is denied" "copilot-cli" `
    '{"sessionId":"s2","hookEventName":"preToolUse","toolName":"view","toolInput":{"path":"/repo/backend/.env"}}' 2

Try-Action "Codex CLI running terraform apply asks the developer" "codex-cli" `
    '{"session_id":"s3","hook_event_name":"PreToolUse","tool_name":"local_shell","tool_input":{"command":"terraform apply -auto-approve"}}' 0

Try-Action "an ordinary build is allowed" "claude-code" `
    '{"session_id":"s4","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"npm run build"}}' 0

# Gemini names its shell tool differently, spells the event differently, and reads a
# differently named field in the reply. Each of those alone would turn a denial into
# permission, because an agent that finds no decision it recognises runs the tool.
Try-Action "Gemini CLI running rm -rf is denied" "gemini-cli" `
    '{"session_id":"s5","hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"cd /tmp && rm -rf /important"}}' 2

# grep_search reads files. Left to the heuristics it matches "search" and would be
# classified as a network fetch, so a rule about reading credentials would not apply.
Try-Action "Gemini searching inside a credential file is denied" "gemini-cli" `
    '{"session_id":"s6","hook_event_name":"BeforeTool","tool_name":"grep_search","tool_input":{"path":"/repo/backend/.env"}}' 2

# Cursor names no tool for a shell command. The kind comes from the event, and
# classifying by the absent tool name would file this as "other" and match no rule.
Try-Action "Cursor running rm -rf is denied, with the kind taken from the event" "cursor" `
    '{"hook_event_name":"beforeShellExecution","command":"cd /tmp && rm -rf /important","cwd":"/repo","sandbox":false}' 2

# Cursor hands the hook the file's entire contents. The guard writes a decision log,
# so anything it reads into the action lands on a developer's disk.
$cursorRead = ('{"hook_event_name":"beforeReadFile","file_path":"/repo/backend/.env","content":"AWS_SECRET=SHOULD-NEVER-BE-LOGGED","user_email":"dev@example.com"}' |
    & $reeve guard --agent cursor --policy $policy --log $decisions 2>&1 | Out-String)
$cursorLog = Get-Content $decisions -Raw
Check "Cursor's file read is denied without the file's contents being logged" `
    ($cursorLog -notmatch "SHOULD-NEVER-BE-LOGGED" -and $cursorLog -notmatch "dev@example.com") `
    "the decision log carries content or identity from Cursor's envelope"

$geminiReply = ('{"session_id":"s7","hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"cd /tmp && rm -rf /x"}}' |
    & $reeve guard --agent gemini-cli --policy $policy 2>$null | Out-String)
Check "the reply is in the shape Gemini reads, not another agent's" `
    ($geminiReply -match '"decision"' -and $geminiReply -notmatch '"permissionDecision"') `
    "reply was: $($geminiReply.Trim())"

# A Gemini hook can only allow or deny. An ask it cannot ask is refused rather than
# waved through, because turning a rule that wanted a human decision into one that
# needs none would remove the control without reporting it.
$geminiAsk = ('{"session_id":"s8","hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"terraform apply -auto-approve"}}' |
    & $reeve guard --agent gemini-cli --policy $policy 2>&1 | Out-String)
$geminiAskCode = $LASTEXITCODE
Check "an ask Gemini cannot ask is refused rather than allowed" `
    ($geminiAskCode -eq 2 -and $geminiAsk -match "policy engine") `
    "exit was $geminiAskCode"

Step 5 "Enforcement: what happens when Reeve itself is broken"
Note "This is what separates real enforcement from theatre."
Write-Host ""

Write-Text (Join-Path $Sandbox "bad.yaml") "version: 1`nrules:`n  - id: broken`n    decision: maybe`n"
$payload = '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}'

$null = ($payload | & $reeve guard --agent claude-code --policy (Join-Path $Sandbox "bad.yaml") 2>&1)
Check "an unparseable policy denies, because intent is unknown" ($LASTEXITCODE -eq 2) "exit was $LASTEXITCODE"

$null = ($payload | & $reeve guard --agent claude-code --policy (Join-Path $Sandbox "missing.yaml") 2>&1)
Check "a policy named but missing denies, because it is a misconfiguration" ($LASTEXITCODE -eq 2) "exit was $LASTEXITCODE"

$null = ($payload | & $reeve guard --agent claude-code 2>&1)
Check "no policy at all allows, because there is no intent to violate" ($LASTEXITCODE -eq 0) "exit was $LASTEXITCODE"

$null = ("this is not json" | & $reeve guard --agent claude-code --policy $policy 2>&1)
Check "an unreadable request denies" ($LASTEXITCODE -eq 2) "exit was $LASTEXITCODE"

# A misspelled agent is worse than a missing one: the reply would be shaped for
# nobody, and an agent that recognises nothing in it runs the tool anyway.
$null = ($payload | & $reeve guard --agent gemini --policy $policy 2>&1)
Check "an agent name Reeve does not know denies rather than guessing a reply shape" `
    ($LASTEXITCODE -eq 2) "exit was $LASTEXITCODE"

# A circuit breaker, which is the only rule that matches on what already happened.
# It reads the guard's own decision log, so it is also the only one with a
# prerequisite: without a log it refuses rather than assuming nothing has happened.
$loopPolicy = Join-Path $repo "examples\policy\loop-breaker.yaml"
$loopLog = Join-Path $Sandbox "loop-decisions.jsonl"
$loopPayload = '{"session_id":"loop","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"curl https://api.example/retry"}}'

foreach ($i in 1..21) {
    $null = ($loopPayload | & $reeve guard --agent claude-code --policy $loopPolicy --log $loopLog 2>&1)
    $loopExit = $LASTEXITCODE
}
Check "a command repeated past the ceiling is stopped" ($loopExit -eq 2) "exit was $loopExit after 21 calls"

# The same rule, with nothing to count from. An absent history is not evidence that
# nothing happened, so it must refuse rather than wave the action through.
$null = ($loopPayload | & $reeve guard --agent claude-code --policy $loopPolicy 2>&1)
Check "a counting rule with no log to count from denies, rather than assuming quiet" `
    ($LASTEXITCODE -eq 2) "exit was $LASTEXITCODE"

# A budget, the other rule that depends on a record rather than on the request. It
# totals the event store the collector writes, and its failure modes are the ones
# worth asserting: unreadable refuses, and an agent that reports no cost at all is
# reported as uncovered rather than quietly passing.
$budgetPolicy = Join-Path $repo "examples\policy\budget.yaml"
$budgetStore = Join-Path $Sandbox "budget-events.jsonl"
$budgetPayload = '{"session_id":"spender","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hello"}}'
$stamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

function Add-Cost($amount) {
    $line = '{"time":"' + $stamp + '","kind":"api_request","agent":"claude-code","sessionId":"spender","costUsd":' + $amount + '}'
    Add-Content -Path $budgetStore -Value $line -Encoding utf8
}

Set-Content -Path $budgetStore -Value "" -Encoding utf8
1..9 | ForEach-Object { Add-Cost "1.00" }

$null = ($budgetPayload | & $reeve guard --agent claude-code --policy $budgetPolicy --store $budgetStore 2>&1)
$budgetUnder = $LASTEXITCODE

# The tenth dollar reaches the limit exactly, and the eleventh passes it. A cap of
# ten that refuses at ten is a cap of just under ten.
Add-Cost "1.00"
$null = ($budgetPayload | & $reeve guard --agent claude-code --policy $budgetPolicy --store $budgetStore 2>&1)
$budgetAt = $LASTEXITCODE

Add-Cost "5.00"
$budgetOver = ($budgetPayload | & $reeve guard --agent claude-code --policy $budgetPolicy --store $budgetStore 2>&1 | Out-String)

Check "a budget does not fire under the limit, or exactly at it" `
    (($budgetUnder -eq 0) -and ($budgetAt -eq 0)) `
    "nine dollars exited $budgetUnder, ten exited $budgetAt"

Check "a budget fires once spend passes the line" `
    ($budgetOver -match "already spent") `
    $budgetOver

# Another session's spending is not charged to this one.
$otherPayload = '{"session_id":"someone-else","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hello"}}'
$null = ($otherPayload | & $reeve guard --agent claude-code --policy $budgetPolicy --store $budgetStore 2>&1)
Check "one session's overspend does not refuse another session's first call" `
    ($LASTEXITCODE -eq 0) "exit was $LASTEXITCODE"

# No store at all. Zero recorded spend and unreadable spend are not the same claim.
$null = ($budgetPayload | & $reeve guard --agent claude-code --policy $budgetPolicy 2>&1)
Check "a budget with no store to total denies, rather than assuming nothing was spent" `
    ($LASTEXITCODE -eq 2) "exit was $LASTEXITCODE"

# The gap that matters most, because it is silent: an agent whose usage never reaches
# your store keeps a budget at zero forever. Compilation has to say so by name.
$budgetCursor = (& $reeve policy compile $budgetPolicy --agent cursor --out (Join-Path $dist "budget") 2>&1 | Out-String)
Check "a budget on an agent that reports no cost is reported as covered by nothing" `
    ($budgetCursor -match "NOT ENFORCED ANYWHERE") `
    "reported as though the guard had it covered"

$budgetClaude = (& $reeve policy compile $budgetPolicy --agent claude-code --out (Join-Path $dist "budget-cc") 2>&1 | Out-String)
Check "the same budget is guard-enforced where cost does reach the store" `
    (-not ($budgetClaude -match "NOT ENFORCED ANYWHERE")) `
    "reported as unenforceable on an agent that exports cost"


# ------------------------------------------------------------ telemetry ----

Step 6 "Telemetry: receive what agents report, normalise it, price it"

if ($Port -eq 0) { $Port = Find-FreePort }
Note "using port $Port (chosen by the OS, so an existing collector on 4317 or 4318 does not clash)"

$events = Join-Path $Sandbox "events.jsonl"
$collectorOut = Join-Path $Sandbox "collector.log"
$collectorErr = Join-Path $Sandbox "collector.err"

# Paths are quoted because Start-Process joins ArgumentList into a single command
# line, and any directory containing a space would otherwise be split in two.
$collector = Start-Process -FilePath $reeve -PassThru -NoNewWindow `
    -RedirectStandardOutput $collectorOut -RedirectStandardError $collectorErr `
    -ArgumentList @("collect", "--addr", "127.0.0.1:$Port",
                    "--store", "`"$events`"", "--teams", "`"$teams`"")

$listening = $false
foreach ($i in 1..20) {
    Start-Sleep -Milliseconds 300
    try {
        Invoke-RestMethod "http://127.0.0.1:$Port/healthz" -TimeoutSec 2 | Out-Null
        $listening = $true
        break
    } catch { }
}
Check "the collector started" $listening (Get-Content $collectorErr -Raw -ErrorAction SilentlyContinue)

if ($listening) {
    try {
        $claude = @'
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
'@
        $copilot = @'
{"resourceMetrics":[{"resource":{"attributes":[
 {"key":"service.name","value":{"stringValue":"copilot"}},
 {"key":"user.email","value":{"stringValue":"contractor@partner.io"}},
 {"key":"team.id","value":{"stringValue":"someone-elses-budget"}},
 {"key":"vcs.repository.name","value":{"stringValue":"billing-api"}}]},
 "scopeMetrics":[{"metrics":[
  {"name":"gen_ai.client.token.usage","sum":{"dataPoints":[
    {"asInt":"45000","attributes":[{"key":"gen_ai.token.type","value":{"stringValue":"input"}},{"key":"gen_ai.request.model","value":{"stringValue":"gpt-5.6-sol"}}]},
    {"asInt":"9000","attributes":[{"key":"gen_ai.token.type","value":{"stringValue":"output"}},{"key":"gen_ai.request.model","value":{"stringValue":"gpt-5.6-sol"}}]}]}}]}]}]}
'@
        $codex = @'
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
'@
        $gemini = @'
{"resourceMetrics":[{"resource":{"attributes":[
 {"key":"service.name","value":{"stringValue":"gemini-cli"}},
 {"key":"user.email","value":{"stringValue":"dev3@example.com"}},
 {"key":"vcs.repository.name","value":{"stringValue":"payment-service"}}]},
 "scopeMetrics":[{"metrics":[
  {"name":"gemini_cli.token.usage","sum":{"dataPoints":[
    {"asInt":"50000","attributes":[{"key":"type","value":{"stringValue":"input"}},{"key":"model","value":{"stringValue":"gemini-3-pro"}}]},
    {"asInt":"7000","attributes":[{"key":"type","value":{"stringValue":"output"}},{"key":"model","value":{"stringValue":"gemini-3-pro"}}]}]}}]}]}]}
'@
        $h = @{ "Content-Type" = "application/json" }
        Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$Port/v1/metrics" -Headers $h -Body $claude | Out-Null
        Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$Port/v1/metrics" -Headers $h -Body $copilot | Out-Null
        Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$Port/v1/logs" -Headers $h -Body $codex | Out-Null
        Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$Port/v1/metrics" -Headers $h -Body $gemini | Out-Null

        $stats = Invoke-RestMethod "http://127.0.0.1:$Port/stats"
        Note "batches received: $($stats.batchesReceived), events written: $($stats.eventsWritten)"
        Check "all four agents' telemetry was accepted" ($stats.batchesReceived -eq 4)
        Check "events were normalised and stored" ($stats.eventsWritten -ge 10) "wrote $($stats.eventsWritten)"
    } finally {
        Stop-Process -Id $collector.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
    }
}

Step 7 "Two properties the whole design rests on"
Write-Host ""

if (Test-Path $events) {
    $storeText = Get-Content $events -Raw
    Check "a prompt was sent, but its text is not in the store" `
        (-not $storeText.Contains("SECRET-THIS-MUST-NEVER-BE-STORED"))
    Check "a client-asserted team was ignored" `
        (-not $storeText.Contains("someone-elses-budget"))
    Check "attribution resolved from your mapping instead" `
        ($storeText.Contains("platform") -and $storeText.Contains("integrations"))
} else {
    Check "the event store exists" $false "no file at $events"
}

# --------------------------------------------------------------- report ----

Step 8 "The report: cost and policy across every agent at once"
Write-Host ""

if (Test-Path $events) {
    $reportText = (& $reeve report --store $events --decisions $decisions --top 5 2>&1 | Out-String)
    Write-Host $reportText

    Check "cost computed from tokens across four vendors" ($reportText -match "estimated from tokens")
    Check "the vendors' own figure shown separately, not merged" ($reportText -match "vendor cost")
    Check "spend attributed by team" ($reportText -match "By team")
    Check "refusals appear, which no vendor telemetry can report" ($reportText -match "blocked")
}

# ------------------------------------------------------------- install ----

Step 9 "Installing the guard, and taking it back out"
Note "This is the only part of Reeve that writes to an agent's own files."
Note "It runs against the sandbox home, never against yours."
Write-Host ""

# A hook the developer wrote themselves, which must survive both directions.
$instHome = Join-Path $Sandbox "install-home"
New-Item -ItemType Directory -Force -Path (Join-Path $instHome ".claude") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $instHome ".cursor") | Out-Null
$instSettings = Join-Path $instHome ".claude\settings.json"
Write-Text $instSettings @'
{
  "permissions": { "allow": ["Bash(git:*)"] },
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "/usr/local/bin/their-own-hook" }] }
    ]
  }
}
'@

# The install reads the home directory from the environment, so it is redirected
# for exactly the length of this step and put back afterwards.
$savedProfile = $env:USERPROFILE
$savedHome = $env:HOME
$env:USERPROFILE = $instHome
$env:HOME = $instHome

try {
    # --plan must change nothing at all. It is the flag somebody reaches for
    # precisely because they do not trust this yet.
    $before = Get-Content $instSettings -Raw
    $null = (& $reeve install --plan 2>&1)
    $after = Get-Content $instSettings -Raw
    Check "--plan changes nothing" ($before -eq $after) "the settings file was modified by a dry run"

    $installOut = (& $reeve install 2>&1 | Out-String)
    Check "the guard installs in dry run, not enforcing, by default" `
        ($installOut -match "dry run") $installOut

    $settingsNow = Get-Content $instSettings -Raw
    Check "a hook the developer wrote survives the install" `
        ($settingsNow -match "their-own-hook") $settingsNow
    Check "settings that have nothing to do with hooks survive the install" `
        ($settingsNow -match [regex]::Escape('Bash(git:*)')) $settingsNow

    # Cursor fails a hook open unless told otherwise, so an installed hook without
    # failClosed stands down exactly on the machines where it broke.
    $cursorHooks = Join-Path $instHome ".cursor\hooks.json"
    $cursorNow = if (Test-Path $cursorHooks) { Get-Content $cursorHooks -Raw } else { "" }
    Check "the Cursor hook is installed failing closed" `
        ($cursorNow -match '"failClosed": true') $cursorNow

    # Installing twice must refresh rather than register a second time: two hooks
    # decide every action twice and log it twice, doubling every count in the report.
    $null = (& $reeve install 2>&1)
    $entries = ([regex]::Matches((Get-Content $instSettings -Raw), "guard --agent claude-code")).Count
    Check "installing twice registers the guard once" ($entries -eq 1) "found $entries registrations"

    # Registered is not firing. A hook can be in the file, answer perfectly when
    # called by hand, and never once be called by the agent — and from the outside
    # that looks exactly like a machine on which nothing bad happened.
    $doctorOut = (& $reeve doctor 2>&1 | Out-String)
    Check "doctor proves the registered hook actually answers" `
        ($doctorOut -match "answers in") $doctorOut

    # The probe runs the real guard, so it must not write a synthetic action into
    # the record of what an agent actually attempted.
    $docPayload = '{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","tool_input":{"command":"echo hi"}}'
    $docLog = Join-Path $instHome ".reeve\decisions.jsonl"
    $null = ($docPayload | & $reeve guard --agent claude-code `
        --policy (Join-Path $instHome ".reeve\policy.yaml") --log $docLog --dry-run 2>&1)
    $docBefore = if (Test-Path $docLog) { @(Get-Content $docLog).Count } else { 0 }
    $null = (& $reeve doctor 2>&1)
    $docAfter = if (Test-Path $docLog) { @(Get-Content $docLog).Count } else { 0 }
    Check "doctor does not write its own probe into the audit trail" `
        ($docBefore -eq $docAfter) "the log went from $docBefore to $docAfter lines"

    # A hook pointing at a binary that is gone is the commonest way this breaks, and
    # the one that looks like nothing at all. Installed from a copy which is then
    # deleted, so this tests what actually happens rather than what a text
    # substitution can manage.
    $moved = Join-Path $Sandbox "reeve-about-to-move.exe"
    Copy-Item $reeve $moved -Force
    $null = (& $moved install 2>&1)
    Remove-Item $moved -Force
    $null = (& $reeve doctor 2>&1)
    Check "doctor fails when the binary a hook points at is gone" `
        ($LASTEXITCODE -eq 2) "it reported a healthy machine"

    # Put a working hook back, so the uninstall checks below still have ours to remove.
    $null = (& $reeve install 2>&1)

    $null = (& $reeve uninstall 2>&1)
    $afterUninstall = Get-Content $instSettings -Raw
    Check "uninstall removes the guard" `
        (-not ($afterUninstall -match "guard --agent")) "the hook is still there"
    Check "uninstall leaves the developer's own hook alone" `
        ($afterUninstall -match "their-own-hook") "their hook was removed along with ours"
} finally {
    $env:USERPROFILE = $savedProfile
    if ($savedHome) { $env:HOME = $savedHome } else { Remove-Item Env:\HOME -ErrorAction SilentlyContinue }
}

# --------------------------------------------------------------- audit ----

Step 10 "The audit trail: proving the decision log has not been edited"
Note "The only record that an action was refused. As far as the agent is"
Note "concerned it never happened, so nothing else anywhere has a trace of it."
Write-Host ""

# Sealed on a copy, because the checks below deliberately corrupt it and the
# report in step 8 reads the real one.
$auditLog = Join-Path $Sandbox "audit-decisions.jsonl"
Copy-Item $decisions $auditLog -Force

# A log with no seal is not evidence, and must not be reported as verified: an
# empty list of findings is exactly what a clean log looks like too.
$null = (& $reeve audit verify $auditLog 2>&1)
Check "a log that was never sealed is not reported as verified" `
    ($LASTEXITCODE -eq 2) `
    "nothing to check against is not the same as nothing wrong (exit $LASTEXITCODE)"

$null = (& $reeve audit seal $auditLog 2>&1)
$sealRc = $LASTEXITCODE
$null = (& $reeve audit verify $auditLog 2>&1)
$verifyRc = $LASTEXITCODE
Check "a sealed log verifies while it is untouched" `
    (($sealRc -eq 0) -and ($verifyRc -eq 0)) `
    "seal $sealRc, verify $verifyRc"

# Appending is what the guard does all day and must never look like tampering.
$null = ($payload | & $reeve guard --agent claude-code --policy $policy --log $auditLog 2>&1)
$null = (& $reeve audit verify $auditLog 2>&1)
Check "a new decision appended after the seal is not mistaken for tampering" `
    ($LASTEXITCODE -eq 0) "exit was $LASTEXITCODE"

# The edit that matters: a refusal rewritten as an allowance, same shape, same
# line count, nothing else to notice.
$null = (& $reeve audit seal $auditLog 2>&1)
(Get-Content $auditLog) -replace '"effect":"deny"', '"effect":"allow"' |
    Set-Content $auditLog -Encoding utf8
$auditOut = (& $reeve audit verify $auditLog 2>&1 | Out-String)
Check "a refusal rewritten as an allowance is caught" `
    ($LASTEXITCODE -eq 2) $auditOut

# And re-sealing must not quietly bless the new content, which would destroy the
# only evidence the edit ever happened.
$null = (& $reeve audit seal $auditLog 2>&1)
Check "re-sealing an edited log refuses rather than covering it up" `
    ($LASTEXITCODE -ne 0) "exit was $LASTEXITCODE"

# Truncation is the easiest tampering there is, and a hash chain alone cannot see
# it: a prefix of a valid chain is a valid chain. The recorded line count is what
# catches it.
$truncLog = Join-Path $Sandbox "truncated-decisions.jsonl"
Copy-Item $decisions $truncLog -Force
$null = (& $reeve audit seal $truncLog 2>&1)
# Read it fully before writing: piping Get-Content straight into Set-Content on
# the same path leaves the file untouched, which would make this check assert
# that an unmodified log verifies, under a name claiming it caught a deletion.
$firstLine = @(Get-Content $truncLog -TotalCount 1)
Set-Content -Path $truncLog -Value $firstLine -Encoding utf8
if ((@(Get-Content $truncLog)).Count -ne 1) {
    throw "the truncation step did not truncate; this check would prove nothing"
}
$truncOut = (& $reeve audit verify $truncLog 2>&1 | Out-String)
Check "decisions deleted from the end of the log are caught" `
    ($truncOut -match "removed from the end") $truncOut

# ------------------------------------------------------------------ mcp ----

Step 11 "MCP servers: what is connected, against what was approved"
Note "Each one extends the agent's reach into another system, with that"
Note "system's credentials. The list is assembled from the developer's home"
Note "directory and from whatever repository happens to be open."
Write-Host ""

$mcpRegistry = Join-Path $repo "examples\mcp\registry.yaml"
$scanFile = Join-Path $Sandbox "scan.json"
& $reeve scan --dir $project --json 2>$null | Out-File -Encoding utf8 $scanFile

$mcpOut = (& $reeve mcp check $scanFile --registry $mcpRegistry 2>&1 | Out-String)
Show $mcpOut

# Matched on the verdict word rather than a sentence. Explanations are wrapped to
# the terminal width, so any phrase long enough to be worth asserting is also long
# enough to be split across two lines by a later edit.
Check "a server that was reviewed and refused is caught in use" `
    ($mcpOut -match "denied") $mcpOut

Check "a server nobody approved is reported, not ignored" `
    ($mcpOut -match "unregistered") $mcpOut

& $reeve mcp check $scanFile --registry $mcpRegistry --fail-on high > $null 2>&1
Check "the registry check is usable as a gate" ($LASTEXITCODE -eq 2) "exit was $LASTEXITCODE"

# The case the whole design turns on. A server's name is a key the developer chose;
# anything at all can be called github. Matching on the name would report this as
# approved, which is worse than having no check at all.
$impostor = Join-Path $Sandbox "impostor.json"
$before = Get-Content $scanFile -Raw
$after = $before -replace '@modelcontextprotocol/server-github', '@someone-else/server-github'
Set-Content -Path $impostor -Value $after -Encoding utf8
if ($before -eq $after) {
    Check "a server wearing an approved name is caught" $false `
        "the test fixture was not modified, so this would prove nothing"
} else {
    $impOut = (& $reeve mcp check $impostor --registry $mcpRegistry 2>&1 | Out-String)
    Check "a server wearing an approved name is caught" ($impOut -match "mismatch") $impOut
}

# And the genuine server is still approved, or the check above would pass for
# something that simply disapproves of everything.
Check "the genuine approved server is not flagged" ($mcpOut -match "approved\s+\d") $mcpOut

# A registry generated from what is running describes the current state rather than
# recording a decision, so nothing in it may come out pre-approved.
$skel = (& $reeve mcp list $scanFile --as-registry 2>&1 | Out-String)
Check "a generated registry never marks anything approved" `
    (($skel -match "status: trial") -and -not ($skel -match "status: approved")) `
    "whatever was installed would become policy with nobody having looked"

# ------------------------------------------------------------- posture ----

Step 12 "Fleet posture: the same question asked about every machine at once"
Note "Reads files. No listener, no agent, no machine reporting on its own behalf."
Write-Host ""

$fleet = Join-Path $Sandbox "fleet"
New-Item -ItemType Directory -Force -Path (Join-Path $fleet "eu-west") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $fleet "us-east") | Out-Null

# Three scans of this machine, which carry its hostname, plus one that does not.
# Two machines, from four reports.
& $reeve scan --dir $project --json --include-hostname 2>$null |
    Out-File -Encoding utf8 (Join-Path $fleet "eu-west\monday.json")
Copy-Item (Join-Path $fleet "eu-west\monday.json") (Join-Path $fleet "eu-west\tuesday.json")
Copy-Item (Join-Path $fleet "eu-west\monday.json") (Join-Path $fleet "us-east\wednesday.json")
& $reeve scan --dir $project --json 2>$null |
    Out-File -Encoding utf8 (Join-Path $fleet "us-east\anonymous.json")

# An upload that was cut off partway. The machine it came from is exactly the kind
# most likely to be in a state nobody has looked at.
Set-Content -Path (Join-Path $fleet "us-east\interrupted.json") -Value '{"schemaVersion":' -Encoding utf8 -NoNewline

$postureText = (& $reeve posture $fleet --top 4 2>&1 | Out-String)
Show $postureText

Check "three scans of one machine count as one machine" `
    ($postureText -match "machines\s+: 2") `
    "a fleet that rescans nightly would report every number several times over"

Check "the report that arrived truncated is named, not quietly dropped" `
    ($postureText -match "could not be read") `
    "the machines whose scans fail are not a random sample of the fleet"

Check "the count says so when it cannot tell two machines apart" `
    ($postureText -match "carry no hostname")

# Percentages are of the machines running that agent. Of the fleet, a total failure
# confined to one uncommon agent reads as a rounding error and never gets looked at.
Check "a finding is measured against the machines that run that agent" `
    ($postureText -match "of 2 machines with")

& $reeve posture $fleet --fail-on high > $null 2>&1
Check "the gate fails while part of the fleet could not be read" `
    ($LASTEXITCODE -eq 2) `
    "exit was $LASTEXITCODE; passing on the machines that did report is a verdict on the wrong population"

# Any JSON object decodes into a report with every field empty, and a report with no
# agents and no findings is what a perfectly governed machine looks like.
$notReports = Join-Path $Sandbox "not-reports"
New-Item -ItemType Directory -Force -Path $notReports | Out-Null
Set-Content -Path (Join-Path $notReports "package.json") -Value '{"name":"app","version":"1.0.0"}' -Encoding utf8
$wrongText = (& $reeve posture $notReports 2>&1 | Out-String)
Check "the wrong directory is an error rather than a clean bill of health" `
    ($LASTEXITCODE -ne 0) `
    "reported: $wrongText"

# -------------------------------------------------------------- summary ----

$passed = @($script:checks | Where-Object { $_.Ok }).Count
$failed = @($script:checks | Where-Object { -not $_.Ok }).Count

Write-Host ""
Write-Host ("=" * 74) -ForegroundColor DarkGray
if ($failed -eq 0) {
    Write-Host " All $passed checks passed." -ForegroundColor Green
} else {
    Write-Host " $passed passed, $failed FAILED." -ForegroundColor Red
    Write-Host ""
    $script:checks | Where-Object { -not $_.Ok } | ForEach-Object {
        Write-Host "   - $($_.Name)" -ForegroundColor Red
        if ($_.Detail) { Write-Host "     $($_.Detail.Trim())" -ForegroundColor DarkRed }
    }
}
Write-Host ("=" * 74) -ForegroundColor DarkGray

Write-Host ""
Note "Artifacts:"
Note "  events    $events"
Note "  decisions $decisions"
Note "  compiled  $dist"
if (-not $KeepSandbox) {
    Note "Remove with: Remove-Item -Recurse -Force '$Sandbox'"
}

Remove-Item Env:\COPILOT_HOME -ErrorAction SilentlyContinue
Remove-Item Env:\CODEX_HOME -ErrorAction SilentlyContinue
Remove-Item Env:\GEMINI_CLI_SYSTEM_SETTINGS_PATH -ErrorAction SilentlyContinue
Remove-Item Env:\GEMINI_CLI_SYSTEM_DEFAULTS_PATH -ErrorAction SilentlyContinue
$env:USERPROFILE = $realUserProfile
$env:ProgramData = $realProgramData
if ($realHome) { $env:HOME = $realHome } else { Remove-Item Env:\HOME -ErrorAction SilentlyContinue }

if ($failed -gt 0) { exit 1 }
