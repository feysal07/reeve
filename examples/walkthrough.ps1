<#
.SYNOPSIS
    Runs every part of Reeve end to end against a throwaway sandbox, and checks the
    results rather than asking you to read them.

.DESCRIPTION
    Exercises all four planes in order: discovery, policy, enforcement and telemetry.

    Nothing here touches your real agent configuration. Fake Copilot and Codex
    installations are created inside a sandbox directory and pointed at with the
    COPILOT_HOME and CODEX_HOME environment variables, which both agents honour.
    Your own Claude Code configuration is read, but only read.

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
$project = Join-Path $Sandbox "project"
New-Item -ItemType Directory -Force -Path $Sandbox, $copilotHome, $codexHome, $project | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $project ".claude") | Out-Null

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

$env:COPILOT_HOME = $copilotHome
$env:CODEX_HOME = $codexHome
Note "sandbox at $Sandbox"

# ------------------------------------------------------------ discovery ----

Step 1 "Discovery: what is installed, and what it can actually do"
Note "Reads configuration only. Never writes to an agent's files."
Write-Host ""

Show (& $reeve scan --dir $project 2>&1 | Out-String)

$scanJson = (& $reeve scan --dir $project --json 2>&1 | Out-String) | ConvertFrom-Json
$agents = @($scanJson.installations).Count
$findings = @($scanJson.findings).Count

Check "three agents detected" ($agents -eq 3) "found $agents"
Check "findings raised against them" ($findings -ge 15) "found $findings"

# The byte order mark defect made this file read as empty, so assert it directly.
$copilotInst = $scanJson.installations | Where-Object { $_.agent -eq "copilot-cli" }
Check "Copilot's settings were parsed, not silently skipped" `
    ($copilotInst.telemetry.captureContent -eq $true) `
    "captureContent came back as '$($copilotInst.telemetry.captureContent)'"

$codexInst = $scanJson.installations | Where-Object { $_.agent -eq "codex-cli" }
Check "Codex reported as running with no sandbox" `
    ($codexInst.permissions.sandboxMode -eq "danger-full-access") `
    "sandboxMode was '$($codexInst.permissions.sandboxMode)'"

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
Check "configuration produced for all three agents" ($produced.Count -eq 4) "wrote $($produced.Count) files"
Check "coverage reported honestly rather than silently dropped" ($compileText -match "guard-only")

$claudeCfg = Get-Content (Join-Path $dist "claude-code-managed-settings.json") -Raw | ConvertFrom-Json
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
        $h = @{ "Content-Type" = "application/json" }
        Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$Port/v1/metrics" -Headers $h -Body $claude | Out-Null
        Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$Port/v1/metrics" -Headers $h -Body $copilot | Out-Null
        Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$Port/v1/logs" -Headers $h -Body $codex | Out-Null

        $stats = Invoke-RestMethod "http://127.0.0.1:$Port/stats"
        Note "batches received: $($stats.batchesReceived), events written: $($stats.eventsWritten)"
        Check "all three agents' telemetry was accepted" ($stats.batchesReceived -eq 3)
        Check "events were normalised and stored" ($stats.eventsWritten -ge 8) "wrote $($stats.eventsWritten)"
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

    Check "cost computed from tokens across three vendors" ($reportText -match "estimated from tokens")
    Check "the vendors' own figure shown separately, not merged" ($reportText -match "vendor cost")
    Check "spend attributed by team" ($reportText -match "By team")
    Check "refusals appear, which no vendor telemetry can report" ($reportText -match "blocked")
}

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

if ($failed -gt 0) { exit 1 }
