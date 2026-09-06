@echo off
REM ====================================================================
REM Cryptotherm - Windows onboarding launcher.
REM Double-click this file. It elevates to Administrator and runs the
REM PowerShell provisioning script sitting next to it.
REM ====================================================================
setlocal
set "PS1=%~dp0provision-windows.ps1"

REM Are we already admin?
net session >nul 2>&1
if %errorlevel% NEQ 0 (
  echo Requesting Administrator rights...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

echo Running Cryptotherm Windows provisioning...
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%"

echo.
echo Finished. Review the output above.
pause
