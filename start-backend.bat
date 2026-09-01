@echo off
setlocal
cd /d "%~dp0backend" 2>nul || cd /d "%~dp0SIH-2026-DATAXAI\backend"
echo ===================================================
echo Starting NetGuard Backend on http://localhost:8000
echo ===================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [NOTICE] Scapy packet capture on Windows requires Administrator privileges.
    echo If live capture fails, run this script as Administrator or use:
    echo powershell -ExecutionPolicy Bypass -File .\scripts\dev-local-capture.ps1
    echo ===================================================
)
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
) else (
    python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
)
pause
