# =====================================================================
# Install the Cryptotherm Mine Manager on a WINDOWS site box.
# Sets it up as a scheduled task that runs at boot (survives reboots).
#
# Run in an ELEVATED PowerShell (Run as Administrator):
#     Set-ExecutionPolicy Bypass -Scope Process -Force
#     .\install-site-manager.ps1
# =====================================================================
$ErrorActionPreference = 'Stop'

function Say  ($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Warn ($m) { Write-Host "!! $m"  -ForegroundColor Yellow }
function Die  ($m) { Write-Host "X $m"   -ForegroundColor Red; exit 1 }

$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Die "Run this in an elevated PowerShell (Run as Administrator)." }

$Here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$Install = 'C:\CT\mine-manager'
$TaskName = 'CT Mine Manager'

# --- Python -----------------------------------------------------------
$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $py) { $py = (Get-Command python3 -ErrorAction SilentlyContinue).Source }
if (-not $py) {
  Warn "Python not found. Installing via winget..."
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    winget install --id Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
    $py = (Get-Command python -ErrorAction SilentlyContinue).Source
  }
}
if (-not $py) { Die "Install Python 3 from https://python.org and re-run." }
Say "Python: $py"
& $py -m pip install --quiet requests

# --- Files ------------------------------------------------------------
Say "Installing to $Install"
New-Item -ItemType Directory -Force -Path $Install, "$Install\reports" | Out-Null
Copy-Item "$Here\mine-manager.py" $Install -Force
if (-not (Test-Path "$Install\mine-manager.conf")) {
  Copy-Item "$Here\mine-manager.conf.example" "$Install\mine-manager.conf"
  Warn "Seeded $Install\mine-manager.conf from example — EDIT IT (subnet, notify, etc.)"
}

# --- Launcher (sets cwd so the DB/reports land in $Install) ------------
$cmd = "$Install\run-mine-manager.cmd"
@"
@echo off
cd /d "$Install"
"$py" "$Install\mine-manager.py" run >> "$Install\mine-manager.out.log" 2>&1
"@ | Set-Content -Path $cmd -Encoding ASCII

# --- Scheduled task at boot (SYSTEM) ----------------------------------
Say "Registering scheduled task '$TaskName' (runs at startup)"
$action  = New-ScheduledTaskAction -Execute $cmd
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
             -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings -Force | Out-Null

Write-Host ""
Say "Installed. Next steps:"
Write-Host "  1. Edit   $Install\mine-manager.conf   (set [site] subnet, [notify], thresholds)"
Write-Host "  2. Secrets as MACHINE env vars (System > Environment Variables), e.g.:"
Write-Host "        setx /M CT_MINER_PASS yourpass"
Write-Host "        setx /M CT_SMTP_PASS  yourpass"
Write-Host "     (SYSTEM tasks read machine env vars; re-register or reboot to pick up new ones.)"
Write-Host "  3. Sanity check now:   & '$py' '$Install\mine-manager.py' status"
Write-Host "  4. Start the task:     Start-ScheduledTask -TaskName '$TaskName'"
Write-Host "     Logs:               Get-Content '$Install\mine-manager.out.log' -Wait"
Warn "Leave dry_run=true for the first day to observe before enabling auto_restart."
