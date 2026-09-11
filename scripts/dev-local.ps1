param(
  [switch]$Check
)

$ErrorActionPreference = "Stop"

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BackendDir = Join-Path $RootDir "backend"
$FrontendDir = Join-Path $RootDir "frontend"
$BackendVenvPython = Join-Path $BackendDir ".venv\Scripts\python.exe"
if (-not (Test-Path $BackendVenvPython)) {
  $BackendVenvPython = Join-Path $RootDir ".venv\Scripts\python.exe"
}
$BackendApiUrl = if ($env:BACKEND_API_URL) { $env:BACKEND_API_URL } else { "http://localhost:8000" }
$AllowedOrigins = if ($env:ALLOWED_ORIGINS) { $env:ALLOWED_ORIGINS } else { "http://localhost:3000" }

function Get-ShellExecutable {
  $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
  if ($pwsh) {
    return $pwsh.Source
  }

  $powershell = Get-Command powershell -ErrorAction SilentlyContinue
  if ($powershell) {
    return $powershell.Source
  }

  throw "PowerShell was not found."
}

function Escape-SingleQuotes {
  param([string]$Value)
  return $Value.Replace("'", "''")
}

function Test-BackendReady {
  if (Test-Path $BackendVenvPython) {
    Write-Host "Backend: ready ($BackendVenvPython)"
    return $true
  }

  try {
    & python -c "import fastapi, uvicorn, dotenv" *> $null
    Write-Host "Backend: ready (system python)"
    return $true
  } catch {
    Write-Host "Backend: missing dependencies. Run .\scripts\setup-local.ps1 first."
    return $false
  }
}

function Test-FrontendReady {
  if (Test-Path (Join-Path $FrontendDir "node_modules")) {
    Write-Host "Frontend: ready"
    return $true
  }

  Write-Host "Frontend: missing dependencies. Run .\scripts\setup-local.ps1 first."
  return $false
}

if ($Check) {
  $backendOk = Test-BackendReady
  $frontendOk = Test-FrontendReady

  if (-not ($backendOk -and $frontendOk)) {
    exit 1
  }

  exit 0
}

if (-not (Test-BackendReady)) {
  exit 1
}

if (-not (Test-FrontendReady)) {
  exit 1
}

$ShellExe = Get-ShellExecutable
$BackendPython = if (Test-Path $BackendVenvPython) { $BackendVenvPython } else { "python" }
$FrontendNext = Join-Path $FrontendDir "node_modules\.bin\next.cmd"

if (-not (Test-Path $FrontendNext)) {
  throw "Next.js local binary is missing. Run .\scripts\setup-local.ps1 first."
}

$EscapedBackendDir = Escape-SingleQuotes $BackendDir
$EscapedFrontendDir = Escape-SingleQuotes $FrontendDir
$EscapedBackendPython = Escape-SingleQuotes $BackendPython
$EscapedBackendApiUrl = Escape-SingleQuotes $BackendApiUrl
$EscapedAllowedOrigins = Escape-SingleQuotes $AllowedOrigins
$EscapedFrontendNext = Escape-SingleQuotes $FrontendNext

$BackendScript = Join-Path $PSScriptRoot "start-backend.ps1"
$FrontendScript = Join-Path $PSScriptRoot "start-frontend.ps1"

Start-Process -FilePath $ShellExe -ArgumentList @("-ExecutionPolicy", "Bypass", "-NoExit", "-File", $BackendScript) -WorkingDirectory $BackendDir | Out-Null
Start-Process -FilePath $ShellExe -ArgumentList @("-ExecutionPolicy", "Bypass", "-NoExit", "-File", $FrontendScript) -WorkingDirectory $FrontendDir | Out-Null

Write-Host ""
Write-Host "NetGuard is starting in separate PowerShell windows."
Write-Host "Frontend: http://localhost:3000"
Write-Host "Backend:  http://localhost:8000"
Write-Host "Close the two PowerShell windows to stop the app."
Write-Host ""
Write-Host "If you want live packet capture on Windows, use .\scripts\dev-local-capture.ps1"
Write-Host "and make sure Npcap is installed."
