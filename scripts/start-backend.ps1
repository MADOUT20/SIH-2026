$ErrorActionPreference = "Stop"
if (-not $PSScriptRoot) {
    if ($MyInvocation.MyCommand.Definition) {
        $PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
    } else {
        $PSScriptRoot = (Get-Location).Path
    }
}
$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BackendDir = Join-Path $RootDir "backend"
$BackendPython = Join-Path $BackendDir ".venv\Scripts\python.exe"
if (-not (Test-Path $BackendPython)) {
    $BackendPython = Join-Path $RootDir ".venv\Scripts\python.exe"
}
if (-not (Test-Path $BackendPython)) {
    $BackendPython = "python"
}

Set-Location $BackendDir
$env:ALLOWED_ORIGINS = if ($env:ALLOWED_ORIGINS) { $env:ALLOWED_ORIGINS } else { "http://localhost:3000" }

Write-Host "Starting NetGuard Backend on http://0.0.0.0:8000..." -ForegroundColor Cyan
& $BackendPython -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
