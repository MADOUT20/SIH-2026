@echo off
setlocal
cd /d "%~dp0frontend" 2>nul || cd /d "%~dp0SIH-2026-DATAXAI\frontend"
echo ===================================================
echo Starting NetGuard Frontend on http://localhost:3000
echo ===================================================
npm run dev
pause
