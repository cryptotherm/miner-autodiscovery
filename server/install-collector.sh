#!/bin/bash
# Install the Cryptotherm Collector as a systemd service.
# Run on the always-on server box (e.g. cthome) as: sudo bash install-collector.sh
set -euo pipefail

INSTALL_DIR="/opt/ct-collector"
SERVICE_NAME="ct-collector"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_USER="${SUDO_USER:-$(whoami)}"

echo "=== Cryptotherm Collector Installer ==="
mkdir -p "$INSTALL_DIR"
cp "$SCRIPT_DIR/collector.py" "$INSTALL_DIR/"
if [ ! -f "$INSTALL_DIR/collector.conf" ]; then
  cp "$SCRIPT_DIR/collector.conf.example" "$INSTALL_DIR/collector.conf"
  echo "!! Seeded $INSTALL_DIR/collector.conf — edit host/port/rate as needed."
fi
chown -R "$RUN_USER" "$INSTALL_DIR"

cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=Cryptotherm Collector + Dashboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$INSTALL_DIR
# Set the shared write token (agents send the same value as CT_SERVER_TOKEN):
#   Environment=CT_SERVER_TOKEN=your-long-random-token
ExecStart=/usr/bin/python3 $INSTALL_DIR/collector.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
echo ""
echo "=== Installed (not started — set CT_SERVER_TOKEN first) ==="
echo "Edit token: sudoedit /etc/systemd/system/${SERVICE_NAME}.service  (add Environment=CT_SERVER_TOKEN=...)"
echo "Start:      sudo systemctl start $SERVICE_NAME"
echo "Dashboard:  http://<this-host>:8090/"
echo "Logs:       journalctl -u $SERVICE_NAME -f"
