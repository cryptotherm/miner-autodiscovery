# =====================================================================
# Cryptotherm - onboard a WINDOWS machine into the ecosystem.
# Installs OpenSSH Server, installs Tailscale, joins the tailnet, and
# authorizes your admin public key(s).
#
# Do not run this directly - double-click  RUN-provision-windows.bat
# (it elevates to Administrator and calls this script). Or, from an
# elevated PowerShell:
#     Set-ExecutionPolicy Bypass -Scope Process -Force
#     .\provision-windows.ps1
#
# Reads ..\config\provision.conf and ..\config\authorized_keys if present.
# =====================================================================
$ErrorActionPreference = 'Stop'

function Say  ($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Warn ($m) { Write-Host "!! $m"   -ForegroundColor Yellow }
function Die  ($m) { Write-Host "X $m"    -ForegroundColor Red; exit 1 }

# must be admin
$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Die "Run as Administrator (use RUN-provision-windows.bat)." }

$Here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$CfgDir = Resolve-Path (Join-Path $Here '..\config') -ErrorAction SilentlyContinue
if (-not $CfgDir) { $CfgDir = (Join-Path $Here '..\config') }
$Conf  = Join-Path $CfgDir 'provision.conf'
$Authz = Join-Path $CfgDir 'authorized_keys'

# --- defaults, then parse the shared KEY="value" conf -----------------
$cfg = @{ TS_AUTHKEY=''; TS_HOSTNAME=''; TS_TAGS=''; SSH_ENABLE='1'; ADMIN_USER=''; INSTALL_OUTBOUND_KEY='0' }
if (Test-Path $Conf) {
  Say "Loading $Conf"
  Get-Content $Conf | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith('#') -and $line.Contains('=')) {
      $k,$v = $line.Split('=',2)
      $v = $v.Trim().Trim('"').Trim("'")
      $cfg[$k.Trim()] = $v
    }
  }
} else { Warn "No provision.conf found - running with defaults / interactive login." }

# --- 1) OpenSSH Server -----------------------------------------------
if ($cfg.SSH_ENABLE -eq '1') {
  Say "Installing OpenSSH Server"
  $cap = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
  if ($cap.State -ne 'Installed') { Add-WindowsCapability -Online -Name $cap.Name | Out-Null }
  Set-Service -Name sshd -StartupType Automatic
  Start-Service sshd
  # firewall
  if (-not (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' `
      -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
  }
  Write-Host "   sshd running + set to auto-start"

  # authorize admin public keys
  if (Test-Path $Authz) {
    Say "Authorizing admin key(s)"
    $keys = Get-Content $Authz | Where-Object { $_ -and -not $_.Trim().StartsWith('#') }
    # For admin accounts Windows uses a single machine-wide file:
    $adminKeys = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
    $existing = @()
    if (Test-Path $adminKeys) { $existing = Get-Content $adminKeys }
    foreach ($k in $keys) { if ($existing -notcontains $k) { Add-Content -Path $adminKeys -Value $k } }
    # lock ACL: Administrators + SYSTEM only (required by sshd)
    icacls $adminKeys /inheritance:r | Out-Null
    icacls $adminKeys /grant 'Administrators:F' 'SYSTEM:F' | Out-Null
    Write-Host "   wrote $adminKeys"
  } else {
    Warn "No config\authorized_keys - skipping key authorization."
  }
} else { Warn "SSH_ENABLE=0 - skipping SSH setup." }

# --- 2) hostname (optional) ------------------------------------------
if ($cfg.TS_HOSTNAME) {
  Say "Renaming computer to $($cfg.TS_HOSTNAME) (takes effect after reboot)"
  Rename-Computer -NewName $cfg.TS_HOSTNAME -Force -ErrorAction SilentlyContinue | Out-Null
}

# --- 3) Tailscale ----------------------------------------------------
Say "Installing Tailscale"
$tsExe = 'C:\Program Files\Tailscale\tailscale.exe'
if (-not (Test-Path $tsExe)) {
  $msi = Join-Path $env:TEMP 'tailscale-setup.msi'
  # winget first if available, else download the stable MSI
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    winget install --id Tailscale.Tailscale --silent --accept-package-agreements --accept-source-agreements
  } else {
    Say "Downloading Tailscale MSI"
    Invoke-WebRequest -Uri 'https://pkgs.tailscale.com/stable/tailscale-setup-latest.msi' -OutFile $msi
    Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /quiet /norestart" -Wait
  }
}
if (-not (Test-Path $tsExe)) { Die "Tailscale did not install - install manually from https://tailscale.com/download/windows and re-run." }

Say "Joining the tailnet"
$up = @('up','--unattended')
if ($cfg.TS_HOSTNAME) { $up += "--hostname=$($cfg.TS_HOSTNAME)" }
if ($cfg.TS_TAGS)     { $up += "--advertise-tags=$($cfg.TS_TAGS)" }
if ($cfg.TS_AUTHKEY)  { $up += "--authkey=$($cfg.TS_AUTHKEY)" }
else { Warn "No TS_AUTHKEY - a browser login window will open; approve this machine." }
& $tsExe @up

# --- 4) optional outbound private key --------------------------------
if ($cfg.INSTALL_OUTBOUND_KEY -eq '1') {
  $src = Join-Path $CfgDir 'id_ct'
  if (Test-Path $src) {
    Say "Installing outbound key"
    $dstDir = Join-Path $env:USERPROFILE '.ssh'
    New-Item -ItemType Directory -Force -Path $dstDir | Out-Null
    Copy-Item $src (Join-Path $dstDir 'id_ct') -Force
    icacls (Join-Path $dstDir 'id_ct') /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
  } else { Warn "INSTALL_OUTBOUND_KEY=1 but config\id_ct missing - skipping." }
}

Say "Done. This machine on the tailnet:"
& $tsExe ip -4 2>$null | ForEach-Object { Write-Host "   tailscale IP: $_" }
Write-Host ""
Write-Host "Admins can now reach it with:  ssh <user>@<tailscale-ip>"
Warn "REMINDER: revoke the auth key in the Tailscale admin console when done."
if ($cfg.TS_HOSTNAME) { Warn "Reboot to apply the new computer name." }
