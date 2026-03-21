#!/bin/bash
# Install Cryptotherm Auto-Discovery as a launchd service (macOS)
# Run as: bash install-mac.sh

INSTALL_DIR="$HOME/.ct-autodiscovery"
PLIST="$HOME/Library/LaunchAgents/com.cryptotherm.autodiscovery.plist"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Cryptotherm Miner Auto-Discovery Installer (macOS) ==="

# Install dependencies
echo "Installing Python dependencies..."
export PATH="/opt/homebrew/opt/ruby/bin:/opt/homebrew/bin:$PATH"
pip3 install requests brother_ql qrcode pillow 2>/dev/null

# Copy files
mkdir -p "$INSTALL_DIR"
cp "$SCRIPT_DIR/autodiscovery.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/autodiscovery.conf" "$INSTALL_DIR/"

# Write launchd plist
cat > "$PLIST" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.cryptotherm.autodiscovery</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>$INSTALL_DIR/autodiscovery.py</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$INSTALL_DIR/autodiscovery.log</string>
    <key>StandardErrorPath</key>
    <string>$INSTALL_DIR/autodiscovery.log</string>
</dict>
</plist>
EOF

launchctl unload "$PLIST" 2>/dev/null
launchctl load "$PLIST"
sleep 2
launchctl list | grep cryptotherm

echo ""
echo "=== Installed! ==="
echo "Status:  launchctl list | grep cryptotherm"
echo "Logs:    tail -f $INSTALL_DIR/autodiscovery.log"
echo "Config:  $INSTALL_DIR/autodiscovery.conf"
echo "Unload:  launchctl unload $PLIST"
