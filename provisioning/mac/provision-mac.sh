#!/usr/bin/env bash
# =====================================================================
# Cryptotherm — onboard a macOS machine into the ecosystem.
# Enables Remote Login (SSH), installs Tailscale, joins the tailnet, and
# authorizes your admin public key(s).
#
# RUN (from the USB, in Terminal):
#     bash provision-mac.sh
# It will prompt for your Mac password (sudo) when needed.
#
# Reads ../config/provision.conf and ../config/authorized_keys if present.
# NOTE: Apple restricts unattended setup. A couple of steps may pop a GUI
# permission dialog (Remote Login, Tailscale VPN profile) — approve them.
# =====================================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CFG_DIR="$(cd "$HERE/../config" 2>/dev/null && pwd || echo "$HERE/../config")"
CONF="$CFG_DIR/provision.conf"
AUTHZ="$CFG_DIR/authorized_keys"

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!! %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(uname)" = "Darwin" ] || die "This is the macOS script — use provision-linux.sh on Linux."

TS_AUTHKEY=""; TS_HOSTNAME=""; TS_TAGS=""; SSH_ENABLE=1; ADMIN_USER=""; INSTALL_OUTBOUND_KEY=0
if [ -f "$CONF" ]; then say "Loading $CONF"; . "$CONF"; else warn "No provision.conf found — running interactively."; fi

# On mac, authorized_keys belongs to the logged-in user by default.
[ -n "${ADMIN_USER:-}" ] || ADMIN_USER="$(id -un)"
ADMIN_HOME="$(dscl . -read /Users/"$ADMIN_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
[ -n "$ADMIN_HOME" ] || ADMIN_HOME="$HOME"

# --- 1) Remote Login (SSH server) ------------------------------------
if [ "${SSH_ENABLE:-1}" = "1" ]; then
  say "Enabling Remote Login (SSH)"
  sudo systemsetup -setremotelogin on 2>/dev/null \
    || warn "Could not toggle Remote Login via CLI — enable it in System Settings > General > Sharing > Remote Login."

  if [ -f "$AUTHZ" ]; then
    say "Authorizing admin key(s) for '$ADMIN_USER'"
    mkdir -p "$ADMIN_HOME/.ssh"; chmod 700 "$ADMIN_HOME/.ssh"
    touch "$ADMIN_HOME/.ssh/authorized_keys"
    while IFS= read -r line; do
      case "$line" in ''|\#*) continue ;; esac
      grep -qxF "$line" "$ADMIN_HOME/.ssh/authorized_keys" || echo "$line" >> "$ADMIN_HOME/.ssh/authorized_keys"
    done < "$AUTHZ"
    chmod 600 "$ADMIN_HOME/.ssh/authorized_keys"
    echo "   wrote $ADMIN_HOME/.ssh/authorized_keys"
  else
    warn "No config/authorized_keys — skipping key authorization."
  fi
else
  warn "SSH_ENABLE=0 — skipping SSH setup."
fi

# --- 2) optional outbound private key --------------------------------
if [ "${INSTALL_OUTBOUND_KEY:-0}" = "1" ] && [ -f "$CFG_DIR/id_ct" ]; then
  say "Installing outbound key"
  mkdir -p "$ADMIN_HOME/.ssh"; chmod 700 "$ADMIN_HOME/.ssh"
  cp "$CFG_DIR/id_ct" "$ADMIN_HOME/.ssh/id_ct"; chmod 600 "$ADMIN_HOME/.ssh/id_ct"
  echo "   installed $ADMIN_HOME/.ssh/id_ct"
fi

# --- 3) hostname (optional) ------------------------------------------
if [ -n "${TS_HOSTNAME:-}" ]; then
  say "Setting computer name to '$TS_HOSTNAME'"
  sudo scutil --set HostName "$TS_HOSTNAME" 2>/dev/null || true
  sudo scutil --set LocalHostName "$TS_HOSTNAME" 2>/dev/null || true
  sudo scutil --set ComputerName "$TS_HOSTNAME" 2>/dev/null || true
fi

# --- 4) Tailscale ----------------------------------------------------
say "Installing Tailscale"
if command -v tailscale >/dev/null 2>&1; then
  TS_BIN="$(command -v tailscale)"
elif command -v brew >/dev/null 2>&1; then
  brew install tailscale
  sudo "$(brew --prefix)/bin/tailscaled" install-system-daemon 2>/dev/null || true
  TS_BIN="$(brew --prefix)/bin/tailscale"
else
  warn "Homebrew not found. Install the Tailscale app instead:"
  warn "   https://tailscale.com/download/mac   (or:  /usr/bin/ruby -e \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\" to get brew, then re-run)"
  TS_BIN=""
fi

if [ -n "${TS_BIN:-}" ]; then
  say "Joining the tailnet"
  UP_ARGS=(--ssh)
  [ -n "${TS_HOSTNAME:-}" ] && UP_ARGS+=(--hostname="$TS_HOSTNAME")
  [ -n "${TS_TAGS:-}" ]     && UP_ARGS+=(--advertise-tags="$TS_TAGS")
  if [ -n "${TS_AUTHKEY:-}" ]; then
    sudo "$TS_BIN" up --authkey="$TS_AUTHKEY" "${UP_ARGS[@]}"
  else
    warn "No TS_AUTHKEY — interactive login; approve the URL it prints."
    sudo "$TS_BIN" up "${UP_ARGS[@]}"
  fi
  say "Done. This machine on the tailnet:"
  "$TS_BIN" ip -4 2>/dev/null | sed 's/^/   tailscale IP: /' || true
fi

echo ""
echo "Admins can now reach it with:  ssh $ADMIN_USER@<tailscale-ip>"
warn "REMINDER: revoke the auth key in the Tailscale admin console when done."
