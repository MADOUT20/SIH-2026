$ErrorActionPreference = "Stop"
if (-not $PSScriptRoot) {
    if ($MyInvocation.MyCommand.Definition) {
        $PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
    } else {
        $PSScriptRoot = (Get-Location).Path
    }
}
$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$FrontendDir = Join-Path $RootDir "frontend"

Set-Location $FrontendDir
$env:BACKEND_API_URL = if ($env:BACKEND_API_URL) { $env:BACKEND_API_URL } else { "http://localhost:8000" }
$env:NEXT_PUBLIC_API_URL = if ($env:NEXT_PUBLIC_API_URL) { $env:NEXT_PUBLIC_API_URL } else { "http://localhost:8000" }

Write-Host "Starting NetGuard Frontend on http://localhost:3000..." -ForegroundColor Cyan
npm run dev
