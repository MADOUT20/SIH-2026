@echo off
setlocal
cd /d "%~dp0frontend"
echo ===================================================
echo Starting NetGuard Frontend on http://localhost:3000
echo ===================================================
npm run dev
pause
