#!/bin/bash
# Install Cryptotherm Auto-Discovery as a systemd service (Linux/CTHome)
# Run as: sudo bash install-linux.sh

INSTALL_DIR="/opt/ct-autodiscovery"
SERVICE_NAME="ct-autodiscovery"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Cryptotherm Miner Auto-Discovery Installer (Linux) ==="

# Install dependencies
echo "Installing Python dependencies..."
pip3 install requests brother_ql qrcode pillow 2>/dev/null || \
  python3 -m pip install requests brother_ql qrcode pillow

# Copy files
mkdir -p "$INSTALL_DIR"
cp "$SCRIPT_DIR/autodiscovery.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/autodiscovery.conf" "$INSTALL_DIR/"

# Write systemd unit
cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=Cryptotherm Miner Auto-Discovery
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/autodiscovery.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME
systemctl status $SERVICE_NAME --no-pager

echo ""
echo "=== Installed! ==="
echo "Status:  systemctl status $SERVICE_NAME"
echo "Logs:    journalctl -u $SERVICE_NAME -f"
echo "Config:  $INSTALL_DIR/autodiscovery.conf"
