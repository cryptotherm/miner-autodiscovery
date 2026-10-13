#!/usr/bin/env bash
# =====================================================================
# Cryptotherm — onboard a LINUX machine into the ecosystem.
# Installs an SSH server, installs Tailscale, joins the tailnet, and
# authorizes your admin public key(s).
#
# RUN (from the USB, as root):
#     sudo bash provision-linux.sh
#
# Reads ../config/provision.conf and ../config/authorized_keys if present.
# =====================================================================
set -euo pipefail

# --- locate the kit + config -----------------------------------------
HERE="$(cd "$(dirname "$0")" && pwd)"
CFG_DIR="$(cd "$HERE/../config" && pwd 2>/dev/null || echo "$HERE/../config")"
CONF="$CFG_DIR/provision.conf"
AUTHZ="$CFG_DIR/authorized_keys"

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!! %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run me with sudo:  sudo bash provision-linux.sh"

# --- defaults, then load config --------------------------------------
TS_AUTHKEY=""; TS_HOSTNAME=""; TS_TAGS=""; SSH_ENABLE=1; ADMIN_USER=""
INSTALL_OUTBOUND_KEY=0
if [ -f "$CONF" ]; then say "Loading $CONF"; . "$CONF"; else warn "No provision.conf found — running interactively."; fi

# Figure out which normal user gets the authorized_keys.
if [ -z "${ADMIN_USER:-}" ]; then ADMIN_USER="${SUDO_USER:-root}"; fi
ADMIN_HOME="$(getent passwd "$ADMIN_USER" | cut -d: -f6)"
[ -n "$ADMIN_HOME" ] || die "Cannot resolve home dir for user '$ADMIN_USER' (set ADMIN_USER in provision.conf)."

# --- package manager abstraction -------------------------------------
if   command -v apt-get >/dev/null 2>&1; then PM=apt
elif command -v dnf     >/dev/null 2>&1; then PM=dnf
elif command -v yum     >/dev/null 2>&1; then PM=yum
elif command -v pacman  >/dev/null 2>&1; then PM=pacman
elif command -v zypper  >/dev/null 2>&1; then PM=zypper
else die "Unsupported distro (no apt/dnf/yum/pacman/zypper)."; fi

pkg_install() {
  case "$PM" in
    apt)    DEBIAN_FRONTEND=noninteractive apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
    dnf)    dnf install -y "$@" ;;
    yum)    yum install -y "$@" ;;
    pacman) pacman -Sy --noconfirm "$@" ;;
    zypper) zypper --non-interactive install "$@" ;;
  esac
}

# --- 1) base tools ---------------------------------------------------
say "Ensuring curl is present"
command -v curl >/dev/null 2>&1 || pkg_install curl

# --- 2) SSH server ---------------------------------------------------
if [ "${SSH_ENABLE:-1}" = "1" ]; then
  say "Installing + enabling SSH server"
  case "$PM" in
    apt|zypper) pkg_install openssh-server ;;
    pacman)     pkg_install openssh ;;
    *)          pkg_install openssh-server ;;
  esac
  # service name is 'ssh' on Debian/Ubuntu, 'sshd' elsewhere
  if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service'; then SSHSVC=ssh; else SSHSVC=sshd; fi
  systemctl enable --now "$SSHSVC" 2>/dev/null || service "$SSHSVC" start || warn "Could not start $SSHSVC via systemd/service."
  echo "   ssh service: $SSHSVC"

  # authorize admin public keys
  if [ -f "$AUTHZ" ]; then
    say "Authorizing admin key(s) for user '$ADMIN_USER'"
    install -d -m 700 -o "$ADMIN_USER" -g "$(id -gn "$ADMIN_USER")" "$ADMIN_HOME/.ssh"
    # append only keys not already present; skip comment/blank lines
    touch "$ADMIN_HOME/.ssh/authorized_keys"
    while IFS= read -r line; do
      case "$line" in ''|\#*) continue ;; esac
      grep -qxF "$line" "$ADMIN_HOME/.ssh/authorized_keys" || echo "$line" >> "$ADMIN_HOME/.ssh/authorized_keys"
    done < "$AUTHZ"
    chown "$ADMIN_USER":"$(id -gn "$ADMIN_USER")" "$ADMIN_HOME/.ssh/authorized_keys"
    chmod 600 "$ADMIN_HOME/.ssh/authorized_keys"
    echo "   wrote $ADMIN_HOME/.ssh/authorized_keys"
  else
    warn "No config/authorized_keys file — skipping key authorization."
    warn "Admins won't be able to key-auth in until you add one."
  fi
else
  warn "SSH_ENABLE=0 — skipping SSH setup."
fi

# --- 3) optional outbound private key --------------------------------
if [ "${INSTALL_OUTBOUND_KEY:-0}" = "1" ]; then
  if [ -f "$CFG_DIR/id_ct" ]; then
    say "Installing outbound key for '$ADMIN_USER'"
    install -d -m 700 -o "$ADMIN_USER" -g "$(id -gn "$ADMIN_USER")" "$ADMIN_HOME/.ssh"
    install -m 600 -o "$ADMIN_USER" -g "$(id -gn "$ADMIN_USER")" "$CFG_DIR/id_ct" "$ADMIN_HOME/.ssh/id_ct"
    echo "   installed $ADMIN_HOME/.ssh/id_ct"
  else
    warn "INSTALL_OUTBOUND_KEY=1 but config/id_ct not found — skipping."
  fi
fi

# --- 4) hostname (optional) ------------------------------------------
if [ -n "${TS_HOSTNAME:-}" ]; then
  say "Setting hostname to '$TS_HOSTNAME'"
  hostnamectl set-hostname "$TS_HOSTNAME" 2>/dev/null || echo "$TS_HOSTNAME" > /etc/hostname
fi

# --- 5) Tailscale ----------------------------------------------------
say "Installing Tailscale"
if ! command -v tailscale >/dev/null 2>&1; then
  curl -fsSL https://tailscale.com/install.sh | sh
fi
systemctl enable --now tailscaled 2>/dev/null || warn "tailscaled not under systemd; continuing."

say "Joining the tailnet"
UP_ARGS=(--ssh)
[ -n "${TS_HOSTNAME:-}" ] && UP_ARGS+=(--hostname="$TS_HOSTNAME")
[ -n "${TS_TAGS:-}" ]     && UP_ARGS+=(--advertise-tags="$TS_TAGS")
if [ -n "${TS_AUTHKEY:-}" ]; then
  tailscale up --authkey="$TS_AUTHKEY" "${UP_ARGS[@]}"
else
  warn "No TS_AUTHKEY set — starting interactive login."
  warn "Open the URL it prints to approve this machine on your tailnet."
  tailscale up "${UP_ARGS[@]}"
fi

# --- done ------------------------------------------------------------
say "Done. This machine on the tailnet:"
tailscale ip -4 2>/dev/null | sed 's/^/   tailscale IP: /' || true
echo "   tailnet name: $(tailscale status --self --json 2>/dev/null | grep -o '\"DNSName\":[^,]*' | head -1 | cut -d'\"' -f4 || echo '(run: tailscale status)')"
echo ""
echo "Admins can now reach it with:  ssh $ADMIN_USER@<tailscale-ip>"
warn "REMINDER: revoke the auth key in the Tailscale admin console when the batch is onboarded."
