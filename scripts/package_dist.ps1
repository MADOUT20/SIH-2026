$ErrorActionPreference = "Stop"

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$DistDir = Join-Path $RootDir "dist\NetGuard"

Write-Host "Assembling NetGuard Portable Package at $DistDir..."

if (Test-Path $DistDir) {
  Remove-Item -Recurse -Force $DistDir
}

New-Item -ItemType Directory -Path $DistDir | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DistDir "backend") | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DistDir "frontend") | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DistDir "models\trained") | Out-Null

# 1. Copy Backend Executable & Dependencies
Write-Host "Copying backend executable..."
Copy-Item -Recurse (Join-Path $RootDir "dist\netguard-backend\*") (Join-Path $DistDir "backend\")

# 2. Copy Frontend Standalone & Assets
Write-Host "Copying Next.js standalone build & assets..."
Copy-Item -Recurse (Join-Path $RootDir "frontend\.next\standalone\*") (Join-Path $DistDir "frontend\")
New-Item -ItemType Directory -Path (Join-Path $DistDir "frontend\.next\static") -Force | Out-Null
Copy-Item -Recurse (Join-Path $RootDir "frontend\.next\static\*") (Join-Path $DistDir "frontend\.next\static\")
if (Test-Path (Join-Path $RootDir "frontend\public")) {
  Copy-Item -Recurse (Join-Path $RootDir "frontend\public") (Join-Path $DistDir "frontend\")
}

# 3. Copy Model Artifacts & Scripts/Certs
Write-Host "Copying trained model artifacts..."
Copy-Item (Join-Path $RootDir "models\trained\world_model.pth") (Join-Path $DistDir "models\trained\")
Copy-Item (Join-Path $RootDir "models\trained\scaler.pkl") (Join-Path $DistDir "models\trained\")
Copy-Item (Join-Path $RootDir "models\trained\feature_config.json") (Join-Path $DistDir "models\trained\")
Copy-Item (Join-Path $RootDir "models\trained\label_mapping.json") (Join-Path $DistDir "models\trained\")
Copy-Item (Join-Path $RootDir "models\trained\benchmark_metrics.json") (Join-Path $DistDir "models\trained\")

Write-Host "Copying certificates and scripts..."
New-Item -ItemType Directory -Path (Join-Path $DistDir "scripts") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DistDir "certs") -Force | Out-Null
if (Test-Path (Join-Path $RootDir "scripts\https_gateway.py")) {
  Copy-Item (Join-Path $RootDir "scripts\https_gateway.py") (Join-Path $DistDir "scripts\")
}
if (Test-Path (Join-Path $RootDir "scripts\generate_pem_cert.py")) {
  Copy-Item (Join-Path $RootDir "scripts\generate_pem_cert.py") (Join-Path $DistDir "scripts\")
}
if (Test-Path (Join-Path $RootDir "certs\*")) {
  Copy-Item -Recurse (Join-Path $RootDir "certs\*") (Join-Path $DistDir "certs\")
}

# 4. Create Single-Click Launcher Script (start-netguard.bat)
$LauncherScript = @"
@echo off
setlocal
cd /d "%~dp0"

echo ===================================================
echo               NETGUARD WINDOWS LAUNCHER            
echo ===================================================
echo.

:: Check Administrator Privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [NOTICE] Requesting Administrator Elevation for Windows Packet Capture ^& HTTPS Port 443...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Check Npcap Driver
sc query npcap >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Npcap service was not detected!
    echo NetGuard requires Npcap for Windows live packet capture.
    echo Please install Npcap from: https://npcap.com/#download
    echo.
)

:: Check SSL Certificates
if not exist "%~dp0certs\localhost.crt" (
    echo Generating trusted localhost SSL certificate...
    python "%~dp0scripts\generate_pem_cert.py"
)

echo [1/3] Starting NetGuard Backend Engine (Port 8000)...
start "NetGuard Backend Engine" /min "%~dp0backend\netguard-backend.exe"

echo Waiting for backend health readiness...
:wait_backend
timeout /t 1 /nobreak >nul
curl -s http://localhost:8000/health >nul 2>&1
if %errorlevel% neq 0 (
    goto wait_backend
)
echo Backend Engine is HEALTHY!

echo [2/3] Starting NetGuard Next.js Standalone Frontend (Port 3000)...
start "NetGuard UI Server" /min node "%~dp0frontend\server.js"

echo Waiting for frontend readiness...
:wait_frontend
timeout /t 1 /nobreak >nul
curl -s http://localhost:3000/dashboard >nul 2>&1
if %errorlevel% neq 0 (
    goto wait_frontend
)
echo Frontend UI Server is READY!

echo [3/3] Starting NetGuard Unified HTTPS Gateway (Port 443)...
start "NetGuard HTTPS Gateway" /min python "%~dp0scripts\https_gateway.py"

echo Waiting for HTTPS Gateway readiness...
:wait_gateway
timeout /t 1 /nobreak >nul
curl -k -s https://localhost/health >nul 2>&1
if %errorlevel% neq 0 (
    goto wait_gateway
)
echo Unified HTTPS Gateway is LIVE!

echo.
echo ===================================================
echo   Opening NetGuard Dashboard at https://localhost/  
echo ===================================================
start https://localhost/

echo.
echo NetGuard is running! Close this window to stop NetGuard.
pause
"@

Set-Content -Path (Join-Path $DistDir "start-netguard.bat") -Value $LauncherScript -Encoding ascii

Write-Host "NetGuard Portable Package assembled successfully at: $DistDir"

