<#
.SYNOPSIS
    Register (or refresh) the SFI audit MCP server in the Copilot CLI config.

.DESCRIPTION
    Resolves every path relative to this script's own location, so the server can
    be deployed from any checkout on any machine without hand-editing absolute
    paths. It merges an "sfi-audit" entry into the Copilot CLI mcp-config.json,
    preserving any other servers already registered, and backs up the existing
    config before writing.

    Python resolution order:
      1. <repo>\.venv\Scripts\python.exe (Windows) or <repo>/.venv/bin/python
      2. -PythonPath argument, if supplied
      3. the first `python` found on PATH

.PARAMETER ConfigPath
    Path to the Copilot CLI mcp-config.json. Defaults to
    $HOME\.copilot\mcp-config.json.

.PARAMETER PythonPath
    Explicit Python interpreter to register. Overrides auto-detection.

.PARAMETER WhatIf
    Print the resulting entry without writing the config.

.EXAMPLE
    pwsh -File scripts\register_mcp.ps1
.EXAMPLE
    pwsh -File scripts\register_mcp.ps1 -WhatIf
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [string]$PythonPath,
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'

# --- Resolve repo layout relative to this script ---------------------------- #
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$McpPkg   = Join-Path $RepoRoot 'mcp_server'
$DataDir  = Join-Path $RepoRoot 'data'

foreach ($p in @($McpPkg, $DataDir)) {
    if (-not (Test-Path $p)) {
        throw "Expected path not found: $p (run this from a full SFI checkout)."
    }
}

# --- Resolve the Python interpreter ----------------------------------------- #
if (-not $PythonPath) {
    $venvWin  = Join-Path $RepoRoot '.venv\Scripts\python.exe'
    $venvNix  = Join-Path $RepoRoot '.venv/bin/python'
    if (Test-Path $venvWin) {
        $PythonPath = $venvWin
    } elseif (Test-Path $venvNix) {
        $PythonPath = $venvNix
    } else {
        $cmd = Get-Command python -ErrorAction SilentlyContinue
        if ($cmd) { $PythonPath = $cmd.Source }
    }
}
if (-not $PythonPath -or -not (Test-Path $PythonPath)) {
    throw "Could not resolve a Python interpreter. Create a .venv or pass -PythonPath."
}
$PythonPath = (Resolve-Path $PythonPath).Path

# --- Config location -------------------------------------------------------- #
if (-not $ConfigPath) {
    $ConfigPath = Join-Path $HOME '.copilot\mcp-config.json'
}

# --- Build the sfi-audit entry ---------------------------------------------- #
$entry = [ordered]@{
    tools   = @('*')
    type    = 'local'
    command = $PythonPath
    args    = @('-m', 'sfi_audit.server')
    env     = [ordered]@{
        PYTHONPATH   = $McpPkg
        SFI_DATA_DIR = $DataDir
    }
}

# --- Merge into existing config (preserve other servers) -------------------- #
if (Test-Path $ConfigPath) {
    $raw = Get-Content -Raw -Path $ConfigPath
    try { $config = $raw | ConvertFrom-Json } catch { $config = $null }
    if (-not $config) { $config = [pscustomobject]@{} }
} else {
    New-Item -ItemType Directory -Force -Path (Split-Path $ConfigPath) | Out-Null
    $config = [pscustomobject]@{}
}

if (-not ($config.PSObject.Properties.Name -contains 'mcpServers')) {
    $config | Add-Member -NotePropertyName 'mcpServers' -NotePropertyValue ([pscustomobject]@{})
}

# Re-add sfi-audit (overwrites a stale entry, keeps the rest).
$servers = [ordered]@{}
foreach ($prop in $config.mcpServers.PSObject.Properties) {
    if ($prop.Name -ne 'sfi-audit') { $servers[$prop.Name] = $prop.Value }
}
$servers['sfi-audit'] = $entry
$config.mcpServers = [pscustomobject]$servers

$json = $config | ConvertTo-Json -Depth 10

if ($WhatIf) {
    Write-Host "[WhatIf] Would write to $ConfigPath :`n$json"
    return
}

# --- Back up then write ----------------------------------------------------- #
if (Test-Path $ConfigPath) {
    $backup = "$ConfigPath.bak-$(Get-Date -Format yyyyMMdd-HHmmss)"
    Copy-Item -Path $ConfigPath -Destination $backup -Force
    Write-Host "Backed up existing config -> $backup"
}

Set-Content -Path $ConfigPath -Value $json -Encoding UTF8
Write-Host "Registered 'sfi-audit' in $ConfigPath"
Write-Host "  command: $PythonPath -m sfi_audit.server"
Write-Host "  PYTHONPATH:   $McpPkg"
Write-Host "  SFI_DATA_DIR: $DataDir"
Write-Host "Restart Copilot CLI (or reload MCP servers) to pick up the change."
