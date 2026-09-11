@echo off
setlocal enabledelayedexpansion

:: Get the current directory path
set "INSTALL_DIR=%~dp0"
:: Remove trailing backslash
set "INSTALL_DIR=%INSTALL_DIR:~0,-1%"

echo [*] Installing NetGuard as a global command...

:: Add the directory to the User PATH environment variable
setx PATH "%PATH%;%INSTALL_DIR%"

:: Create a small wrapper in a more common place if possible,
:: but setx is the standard way to make a folder global.

echo [+] Success! Please restart your terminal/command prompt.
echo You can now run 'run.bat' or just 'python launch.py' from any folder if you use the full path.
echo Note: Since we added the folder to PATH, you can now run 'run.bat' from anywhere.
echo Example: run.bat --file C:\path\to\your\file.pcap
pause
