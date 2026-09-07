#!/bin/bash
set -euo pipefail

# Linux Agent Firewall Setup Script
# Configures UFW (or iptables fallback) for the Agent deployment.
#
# Usage:
#   sudo ./scripts/firewall-setup.sh                # interactive (UFW preferred)
#   sudo ./scripts/firewall-setup.sh --ufw          # force UFW
#   sudo ./scripts/firewall-setup.sh --iptables     # force iptables
#   sudo ./scripts/firewall-setup.sh --dry-run      # print rules without applying
#
# Ports:
#   8443/tcp  - Agent HTTPS endpoint (MCP Server only)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="auto"
DRY_RUN=false

# --- Parse arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ufw) MODE="ufw" ;;
        --iptables) MODE="iptables" ;;
        --dry-run) DRY_RUN=true ;;
        -h|--help)
            echo "Usage: $0 [--ufw|--iptables|--dry-run]"
            echo ""
            echo "Configures firewall rules for Agent deployment."
            echo "  --ufw         Use UFW (Uncomplicated Firewall)"
            echo "  --iptables    Use iptables directly"
            echo "  --dry-run     Print rules without applying"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

# --- Configuration ---
AGENT_PORT="${AGENT_PORT:-8443}"
MCP_SERVER_IP="${MCP_SERVER_IP:-}"    # MCP Server IP address
ALLOW_SSH="${ALLOW_SSH:-yes}"

log() { echo "[firewall] $*"; }

apply_or_print() {
    local desc="$1"
    shift
    if $DRY_RUN; then
        echo "  [DRY-RUN] $*  # $desc"
    else
        "$@"
        log "Applied: $desc"
    fi
}

# --- Detect firewall backend ---
detect_backend() {
    if [[ "$MODE" != "auto" ]]; then
        echo "$MODE"
        return
    fi
    if command -v ufw &>/dev/null; then
        echo "ufw"
    else
        echo "iptables"
    fi
}

BACKEND="$(detect_backend)"
log "Using firewall backend: $BACKEND"

if [[ -z "$MCP_SERVER_IP" ]]; then
    log "WARNING: MCP_SERVER_IP not set."
    log "  Agent port will be open to all sources."
    log "  Set MCP_SERVER_IP to restrict access to the MCP Server only."
    log "  Press Ctrl+C to cancel, or wait 10 seconds to continue..."
    sleep 10
fi

# --- UFW Rules ---
setup_ufw() {
    log "Configuring UFW..."

    apply_or_print "Default deny incoming" ufw default deny incoming
    apply_or_print "Default allow outgoing" ufw default allow outgoing

    if [[ "$ALLOW_SSH" == "yes" ]]; then
        apply_or_print "Allow SSH" ufw allow 22/tcp comment "SSH"
    fi

    if [[ -n "$MCP_SERVER_IP" ]]; then
        apply_or_print "Allow Agent from MCP Server" ufw allow from "$MCP_SERVER_IP" to any port "$AGENT_PORT" proto tcp comment "Agent (MCP Server)"
    else
        apply_or_print "Allow Agent (all sources)" ufw allow "$AGENT_PORT"/tcp comment "Agent"
    fi

    if $DRY_RUN; then
        echo "  [DRY-RUN] ufw --force enable"
    else
        ufw --force enable
        log "UFW enabled"
    fi

    ufw status verbose
}

# --- iptables Rules ---
setup_iptables() {
    log "Configuring iptables..."

    apply_or_print "Flush existing rules" iptables -F
    apply_or_print "Default drop INPUT" iptables -P INPUT DROP
    apply_or_print "Default accept OUTPUT" iptables -P OUTPUT ACCEPT
    apply_or_print "Default drop FORWARD" iptables -P FORWARD DROP

    apply_or_print "Allow loopback" iptables -A INPUT -i lo -j ACCEPT
    apply_or_print "Allow established" iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    if [[ "$ALLOW_SSH" == "yes" ]]; then
        apply_or_print "Allow SSH" iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    fi

    if [[ -n "$MCP_SERVER_IP" ]]; then
        apply_or_print "Allow Agent from MCP Server" iptables -A INPUT -p tcp -s "$MCP_SERVER_IP" --dport "$AGENT_PORT" -j ACCEPT
    else
        apply_or_print "Allow Agent (all)" iptables -A INPUT -p tcp --dport "$AGENT_PORT" -j ACCEPT
    fi

    apply_or_print "Log dropped (rate-limit)" iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables-dropped: "

    if command -v iptables-save &>/dev/null && [[ -d /etc/iptables ]]; then
        apply_or_print "Save iptables rules" bash -c "iptables-save > /etc/iptables/rules.v4"
    fi

    iptables -L -n -v
}

# --- Main ---
echo "=== Agent Firewall Setup ==="
echo ""
echo "Configuration:"
echo "  Agent port:      $AGENT_PORT"
echo "  MCP Server IP:   ${MCP_SERVER_IP:-"(not set, open to all)"}"
echo "  Allow SSH:       $ALLOW_SSH"
echo "  Dry run:         $DRY_RUN"
echo ""

if [[ "$BACKEND" == "ufw" ]]; then
    setup_ufw
else
    setup_iptables
fi

echo ""
echo "=== Firewall setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Verify: curl -k https://<agent-ip>:$AGENT_PORT/v1/health (from MCP Server)"
echo "  2. Verify: access from unauthorized source is blocked"
echo "  3. Record results in Plane Issue P2-10"
