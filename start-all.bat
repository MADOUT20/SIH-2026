@echo off
setlocal
cd /d "%~dp0"
echo Starting Backend and Frontend...
start "NetGuard Backend (Port 8000)" "%~dp0start-backend.bat"
start "NetGuard Frontend (Port 3000)" "%~dp0start-frontend.bat"
echo Both services launched in separate windows.
