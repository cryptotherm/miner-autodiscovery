@echo off
REM Install Cryptotherm Auto-Discovery as a Windows Task (Alienware)
REM Run as Administrator

SET INSTALL_DIR=%USERPROFILE%\.ct-autodiscovery
SET SCRIPT_DIR=%~dp0

echo === Cryptotherm Miner Auto-Discovery Installer (Windows) ===

REM Install Python dependencies
echo Installing Python dependencies...
pip install requests qrcode pillow 2>NUL

REM Create install dir and copy files
mkdir "%INSTALL_DIR%" 2>NUL
copy "%SCRIPT_DIR%autodiscovery.py" "%INSTALL_DIR%\" >NUL
copy "%SCRIPT_DIR%autodiscovery.conf" "%INSTALL_DIR%\" >NUL

REM Create wrapper bat
echo @echo off > "%INSTALL_DIR%\run.bat"
echo python "%INSTALL_DIR%\autodiscovery.py" >> "%INSTALL_DIR%\run.bat"

REM Create Task Scheduler task
schtasks /delete /tn "CT-AutoDiscovery" /f 2>NUL
schtasks /create ^
  /tn "CT-AutoDiscovery" ^
  /tr "\"%INSTALL_DIR%\run.bat\"" ^
  /sc ONLOGON ^
  /ru "%USERNAME%" ^
  /rl HIGHEST ^
  /f

schtasks /run /tn "CT-AutoDiscovery"
timeout /t 3

schtasks /query /tn "CT-AutoDiscovery" /fo LIST

echo.
echo === Installed! ===
echo Status:  schtasks /query /tn "CT-AutoDiscovery"
echo Logs:    type %INSTALL_DIR%\autodiscovery.log
echo Config:  %INSTALL_DIR%\autodiscovery.conf
echo Stop:    schtasks /end /tn "CT-AutoDiscovery"
