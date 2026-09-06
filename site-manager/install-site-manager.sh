#!/bin/bash
# Install the Cryptotherm Mine Manager as a systemd service on a site box.
# Run as: sudo bash install-site-manager.sh
set -euo pipefail

INSTALL_DIR="/opt/ct-mine-manager"
SERVICE_NAME="ct-mine-manager"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_USER="${SUDO_USER:-$(whoami)}"

echo "=== Cryptotherm Mine Manager Installer ==="

echo "Installing Python dependency (requests)..."
pip3 install requests 2>/dev/null || python3 -m pip install requests

mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/reports"
cp "$SCRIPT_DIR/mine-manager.py" "$INSTALL_DIR/"

# Config: keep an existing one, else seed from the example (edit before it's useful)
if [ ! -f "$INSTALL_DIR/mine-manager.conf" ]; then
  cp "$SCRIPT_DIR/mine-manager.conf.example" "$INSTALL_DIR/mine-manager.conf"
  echo "!! Seeded $INSTALL_DIR/mine-manager.conf from example — EDIT IT (set subnet, notify, etc.)"
fi
chown -R "$RUN_USER" "$INSTALL_DIR"

cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=Cryptotherm Mine Manager
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$INSTALL_DIR
# Put secrets here (SMTP/platform), not in the repo:
#   Environment=CT_SMTP_PASS=...    CT_PLATFORM_TOKEN=...    CT_MINER_PASS=...
ExecStart=/usr/bin/python3 $INSTALL_DIR/mine-manager.py run
Restart=always
RestartSec=15
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
echo ""
echo "=== Installed (not started — edit the config first) ==="
echo "Edit:    $INSTALL_DIR/mine-manager.conf"
echo "Start:   sudo systemctl start $SERVICE_NAME"
echo "Logs:    journalctl -u $SERVICE_NAME -f"
echo "Ad hoc:  python3 $INSTALL_DIR/mine-manager.py status"
