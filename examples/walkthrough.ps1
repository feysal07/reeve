<#
.SYNOPSIS
    Runs every part of Reeve end to end against a throwaway sandbox.

.DESCRIPTION
    Exercises all four planes in order: discovery, policy, enforcement and telemetry.

    Nothing here touches your real agent configuration. Fake Copilot and Codex
    installations are created inside a sandbox directory and pointed at with the
    COPILOT_HOME and CODEX_HOME environment variables, which both agents honour.
    Your own Claude Code configuration is read, but only read.

.EXAMPLE
    .\examples\walkthrough.ps1

.EXAMPLE
    .\examples\walkthrough.ps1 -Sandbox C:\temp\reeve-demo -KeepSandbox
#>
[CmdletBinding()]
param(
    [string]$Sandbox = (Join-Path $env:TEMP "reeve-walkthrough"),
    [switch]$KeepSandbox,
    [string]$Port = "4318"
)

# Native commands here write explanations to stderr as a normal part of their job:
# the guard puts the reason a developer was blocked there. Windows PowerShell turns
# any native stderr into a terminating error when ErrorActionPreference is Stop, which
# would abort the walkthrough on its first successful denial.
$ErrorActionPreference = "Continue"

# PowerShell encodes what it pipes into a native command. Without this, a payload can
# arrive with a byte order mark or in the wrong code page.
$OutputEncoding = New-Object System.Text.UTF8Encoding $false
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false

# Resolve the repository root from this script's location, so the walkthrough works
# whatever directory it is invoked from.
$repo = Split-Path -Parent $PSScriptRoot
$reeve = Join-Path $repo "bin\reeve.exe"
$policy = Join-Path $repo "examples\policy\baseline.yaml"
$teams = Join-Path $repo "examples\telemetry\teams.yaml"

function Step($n, $title) {
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor DarkGray
    Write-Host " $n. $title" -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor DarkGray
    Write-Host ""
}

function Note($text) { Write-Host "  $text" -ForegroundColor DarkGray }

# Write-Text writes UTF-8 without a byte order mark. Set-Content -Encoding utf8 on
# Windows PowerShell 5.1 adds one, and a BOM in a config file is a real-world hazard:
# Reeve strips it when reading, but the agents themselves may not.
function Write-Text($path, $content) {
    [System.IO.File]::WriteAllText($path, $content, (New-Object System.Text.UTF8Encoding $false))
}

# ---------------------------------------------------------------- build ----

Step 0 "Build"

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw "Go is not on PATH. Open a new terminal, or add C:\Users\$env:USERNAME\tools\go\bin."
}
Push-Location $repo
try {
    go build -o bin\reeve.exe .\cmd\reeve
    if ($LASTEXITCODE -ne 0) { throw "build failed" }
} finally {
    Pop-Location
}
Note "built $reeve"
& $reeve version

# -------------------------------------------------------------- sandbox ----

if (Test-Path $Sandbox) { Remove-Item -Recurse -Force $Sandbox }
New-Item -ItemType Directory -Force -Path $Sandbox | Out-Null
$copilotHome = Join-Path $Sandbox "copilot-home"
$codexHome = Join-Path $Sandbox "codex-home"
$project = Join-Path $Sandbox "project"
New-Item -ItemType Directory -Force -Path $copilotHome, $codexHome, $project | Out-Null

# A project with MCP servers defined by the repository, which is a supply-chain path
# into every machine that opens it.
@'
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
'@ | ForEach-Object { Write-Text (Join-Path $project ".mcp.json") $_ }

New-Item -ItemType Directory -Force -Path (Join-Path $project ".claude") | Out-Null
@'
{
  "permissions": {
    "defaultMode": "acceptEdits",
    "allow": ["Bash(git:*)"],
    "deny": ["Read(./.env)"]
  }
}
'@ | ForEach-Object { Write-Text (Join-Path $project ".claude\settings.json") $_ }

# A Copilot install exporting prompt content, which is the finding most worth seeing.
@'
{
  "model": "auto",
  "permissions": { "deny": ["Read(**/.env)"] },
  "telemetry": { "enabled": true, "endpoint": "https://otel.corp.internal", "captureContent": true }
}
'@ | ForEach-Object { Write-Text (Join-Path $copilotHome "settings.json") $_ }

@'
{
  "mcpServers": {
    "internal": {
      "type": "http",
      "url": "https://mcp.corp.internal",
      "headers": { "Authorization": "Bearer fake-value-for-the-demo" }
    }
  }
}
'@ | ForEach-Object { Write-Text (Join-Path $copilotHome "mcp-config.json") $_ }

# A Codex install running with no sandbox and no prompting at all.
@'
model = "gpt-5.6-sol"
approval_policy = "never"
sandbox_mode = "danger-full-access"

[mcp_servers.jira]
command = "mcp-jira"
env = { JIRA_API_TOKEN = "fake-value-for-the-demo" }

[otel]
exporter = "none"
'@ | ForEach-Object { Write-Text (Join-Path $codexHome "config.toml") $_ }

$env:COPILOT_HOME = $copilotHome
$env:CODEX_HOME = $codexHome

Note "sandbox at $Sandbox"

# ------------------------------------------------------------ discovery ----

Step 1 "Discovery: what is installed and what can it do"
Note "Reads configuration only. Never writes to an agent's files."

& $reeve scan --dir $project

# --------------------------------------------------------------- policy ----

Step 2 "Policy: validate it, then try it before it blocks anyone"

& $reeve policy check $policy

Write-Host ""
Note "A destructive command:"
& $reeve policy test $policy --command "rm -rf /var/data"
if ($LASTEXITCODE -eq 2) { Note "exit 2, so this works as a CI assertion" }

Write-Host ""
Note "Reading a credential file:"
& $reeve policy test $policy --kind read --path "services/api/.env"

Write-Host ""
Note "An ordinary build, which must not be blocked:"
& $reeve policy test $policy --command "go build ./..."

# -------------------------------------------------------------- compile ----

Step 3 "Compile: the same policy as each agent's own configuration"
Note "The coverage report is the part that matters. Native configuration cannot"
Note "express everything the guard can, and the compiler says so rather than"
Note "quietly dropping what it cannot carry."

$dist = Join-Path $Sandbox "dist"
& $reeve policy compile $policy --out $dist --platform linux
Write-Host ""
Note "Files written:"
Get-ChildItem $dist | ForEach-Object { Note "  $($_.Name)  ($($_.Length) bytes)" }

# ---------------------------------------------------------- enforcement ----

Step 4 "Enforcement: the guard decides before an action happens"
Note "Each payload below is the real shape that agent sends to a pre-tool hook."

$decisions = Join-Path $Sandbox "decisions.jsonl"

function Try-Action($label, $agent, $payload, $expected) {
    Write-Host ""
    Write-Host "  $label" -ForegroundColor Yellow
    Note "  expecting: $expected"
    $payload | & $reeve guard --agent $agent --policy $policy --log $decisions
    Note "  exit code: $LASTEXITCODE"
}

Try-Action "Claude Code running rm -rf" "claude-code" `
    '{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /important"}}' `
    "DENY, exit 2"

Try-Action "Copilot CLI reading a .env file" "copilot-cli" `
    '{"sessionId":"s2","hookEventName":"preToolUse","toolName":"view","toolInput":{"path":"/repo/backend/.env"}}' `
    "DENY, exit 2"

Try-Action "Codex CLI running terraform apply" "codex-cli" `
    '{"session_id":"s3","hook_event_name":"PreToolUse","tool_name":"local_shell","tool_input":{"command":"terraform apply -auto-approve"}}' `
    "ASK, exit 0, decision handed to the developer"

Try-Action "Claude Code running an ordinary build" "claude-code" `
    '{"session_id":"s4","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"npm run build"}}' `
    "ALLOW, exit 0"

Step 5 "Enforcement: what happens when Reeve itself is broken"
Note "This is what separates real enforcement from theatre."

Write-Host ""
Write-Host "  A policy file that exists but will not parse" -ForegroundColor Yellow
Note "  expecting: DENY. Intent is unknown, and pretending to enforce is worse than stopping."
"version: 1`nrules:`n  - id: broken`n    decision: maybe`n" | ForEach-Object { Write-Text (Join-Path $Sandbox "bad.yaml") $_ }
'{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' |
    & $reeve guard --agent claude-code --policy (Join-Path $Sandbox "bad.yaml")
Note "  exit code: $LASTEXITCODE"

Write-Host ""
Write-Host "  No policy configured anywhere" -ForegroundColor Yellow
Note "  expecting: ALLOW. There is no operator intent to violate."
'{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' |
    & $reeve guard --agent claude-code
Note "  exit code: $LASTEXITCODE"

# ------------------------------------------------------------ telemetry ----

Step 6 "Telemetry: receive what agents report, normalise it, price it"

$events = Join-Path $Sandbox "events.jsonl"
$log = Join-Path $Sandbox "collector.log"

# Paths are quoted because Start-Process joins ArgumentList into one command line,
# and any directory containing a space would otherwise be split into two arguments.
$collector = Start-Process -FilePath $reeve -PassThru -NoNewWindow -RedirectStandardOutput $log `
    -RedirectStandardError (Join-Path $Sandbox "collector.err") `
    -ArgumentList @("collect", "--addr", "127.0.0.1:$Port", "--store", "`"$events`"", "--teams", "`"$teams`"")
Start-Sleep -Seconds 2

try {
    Invoke-RestMethod "http://127.0.0.1:$Port/healthz" | Out-Null
    Note "collector listening on port $Port"

    # Three agents, three completely different payload shapes, same measurement.
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

    $h = @{ "Content-Type" = "application/json" }
    Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$Port/v1/metrics" -Headers $h -Body $claude | Out-Null
    Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$Port/v1/metrics" -Headers $h -Body $copilot | Out-Null
    Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$Port/v1/logs" -Headers $h -Body $codex | Out-Null

    $stats = Invoke-RestMethod "http://127.0.0.1:$Port/stats"
    Note "batches received: $($stats.batchesReceived), events written: $($stats.eventsWritten)"
} finally {
    Stop-Process -Id $collector.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
}

Step 7 "Two properties worth checking yourself"

Write-Host "  Prompt content must never reach the store" -ForegroundColor Yellow
if (Select-String -Path $events -Pattern "SECRET-THIS-MUST-NEVER-BE-STORED" -Quiet) {
    Write-Host "  FAIL: prompt text was stored" -ForegroundColor Red
} else {
    Write-Host "  PASS: the prompt was sent but is not in the store" -ForegroundColor Green
}

Write-Host ""
Write-Host "  A client-asserted team must be ignored" -ForegroundColor Yellow
if (Select-String -Path $events -Pattern "someone-elses-budget" -Quiet) {
    Write-Host "  FAIL: the client's own team attribute was believed" -ForegroundColor Red
} else {
    Write-Host "  PASS: attribution came from your mapping, not the payload" -ForegroundColor Green
}

Step 8 "The report: cost and policy across every agent at once"

& $reeve report --store $events --decisions $decisions --top 5

# --------------------------------------------------------------- finish ----

Write-Host ""
Write-Host ("=" * 72) -ForegroundColor DarkGray
Write-Host " Done" -ForegroundColor Cyan
Write-Host ("=" * 72) -ForegroundColor DarkGray
Write-Host ""
Note "Artifacts left behind:"
Note "  events    $events"
Note "  decisions $decisions"
Note "  compiled  $dist"

Remove-Item Env:\COPILOT_HOME -ErrorAction SilentlyContinue
Remove-Item Env:\CODEX_HOME -ErrorAction SilentlyContinue

if (-not $KeepSandbox) {
    Write-Host ""
    Note "Remove the sandbox with:"
    Note "  Remove-Item -Recurse -Force '$Sandbox'"
}
