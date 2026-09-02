#!/bin/bash
set -euo pipefail

# Linux Agent setup script (run as root)
# Creates dedicated user, installs binary and config

USER="lrm-mcp-agent"
GROUP="lrm-mcp-agent"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/lrm-mcp-agent"
DATA_DIR="/var/lib/lrm-mcp-agent"
LOG_DIR="/var/log/lrm-mcp-agent"

echo "=== Linux Agent Setup ==="

# Create group
if ! getent group "$GROUP" > /dev/null 2>&1; then
    groupadd --system "$GROUP"
    echo "Created group: $GROUP"
fi

# Create user
if ! id "$USER" > /dev/null 2>&1; then
    useradd --system --gid "$GROUP" --home-dir "$DATA_DIR" \
        --shell /usr/sbin/nologin --comment "Linux Agent" "$USER"
    echo "Created user: $USER"
fi

# Create directories
mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
chown "$USER:$GROUP" "$DATA_DIR" "$LOG_DIR"
chmod 700 "$DATA_DIR" "$LOG_DIR"

# Install binary (if built)
if [ -f "lrm-mcp-agent" ]; then
    cp lrm-mcp-agent "$INSTALL_DIR/lrm-mcp-agent"
    chmod 755 "$INSTALL_DIR/lrm-mcp-agent"
    echo "Installed binary to $INSTALL_DIR/lrm-mcp-agent"
fi

# Install config (if not exists)
if [ ! -f "$CONFIG_DIR/config.yml" ] && [ -f "config.yml" ]; then
    cp config.yml "$CONFIG_DIR/config.yml"
    chmod 600 "$CONFIG_DIR/config.yml"
    chown "$USER:$GROUP" "$CONFIG_DIR/config.yml"
    echo "Installed config to $CONFIG_DIR/config.yml"
fi

# Install systemd service
if [ -f "scripts/lrm-mcp-agent.service" ]; then
    cp scripts/lrm-mcp-agent.service /etc/systemd/system/lrm-mcp-agent.service
    systemctl daemon-reload
    systemctl enable lrm-mcp-agent
    echo "Installed systemd service"
fi

echo ""
echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Set up tokens: sudo ./scripts/setup-tokens.sh"
echo "  2. Start: systemctl start lrm-mcp-agent"
echo "  3. Check status: systemctl status lrm-mcp-agent"
