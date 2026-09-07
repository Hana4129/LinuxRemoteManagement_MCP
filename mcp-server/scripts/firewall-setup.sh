#!/bin/bash
set -euo pipefail

# MCP Server Firewall Setup Script
# Configures UFW (or iptables fallback) for the MCP Server deployment.
#
# Usage:
#   sudo ./scripts/firewall-setup.sh                # interactive (UFW preferred)
#   sudo ./scripts/firewall-setup.sh --ufw          # force UFW
#   sudo ./scripts/firewall-setup.sh --iptables     # force iptables
#   sudo ./scripts/firewall-setup.sh --dry-run      # print rules without applying
#
# Ports:
#   8080/tcp  - Management Console (management network only)
#   8090/tcp  - MCP HTTP endpoint (user network only)
#   8443/tcp  - Agent endpoint (MCP Server only, configured on Agent side)

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
            echo "Configures firewall rules for MCP Server deployment."
            echo "  --ufw         Use UFW (Uncomplicated Firewall)"
            echo "  --iptables    Use iptables directly"
            echo "  --dry-run     Print rules without applying"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

# --- Configuration (override via environment variables) ---
CONSOLE_PORT="${CONSOLE_PORT:-8080}"
MCP_HTTP_PORT="${MCP_HTTP_PORT:-8090}"
MANAGEMENT_NET="${MANAGEMENT_NET:-}"    # e.g. 10.0.1.0/24
USER_NET="${USER_NET:-}"                # e.g. 10.0.2.0/24
ALLOW_SSH="${ALLOW_SSH:-yes}"           # yes/no

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

# --- UFW Rules ---
setup_ufw() {
    log "Configuring UFW..."

    # Default policies
    apply_or_print "Default deny incoming" ufw default deny incoming
    apply_or_print "Default allow outgoing" ufw default allow outgoing

    # SSH (optional)
    if [[ "$ALLOW_SSH" == "yes" ]]; then
        apply_or_print "Allow SSH" ufw allow 22/tcp comment "SSH"
    fi

    # Console port
    if [[ -n "$MANAGEMENT_NET" ]]; then
        apply_or_print "Allow console from management net" ufw allow from "$MANAGEMENT_NET" to any port "$CONSOLE_PORT" proto tcp comment "MCP Console (mgmt)"
    else
        apply_or_print "Allow console (all sources)" ufw allow "$CONSOLE_PORT"/tcp comment "MCP Console"
    fi

    # MCP HTTP port
    if [[ -n "$USER_NET" ]]; then
        apply_or_print "Allow MCP HTTP from user net" ufw allow from "$USER_NET" to any port "$MCP_HTTP_PORT" proto tcp comment "MCP HTTP (users)"
    else
        apply_or_print "Allow MCP HTTP (all sources)" ufw allow "$MCP_HTTP_PORT"/tcp comment "MCP HTTP"
    fi

    # Enable UFW (idempotent)
    if $DRY_RUN; then
        echo "  [DRY-RUN] ufw --force enable"
    else
        ufw --force enable
        log "UFW enabled"
    fi

    if $DRY_RUN; then
        echo ""
        echo "--- UFW rules that would be applied ---"
        ufw status verbose 2>/dev/null || true
    else
        ufw status verbose
    fi
}

# --- iptables Rules ---
setup_iptables() {
    log "Configuring iptables..."

    # Flush existing rules (careful in production!)
    apply_or_print "Flush existing rules" iptables -F
    apply_or_print "Flush nat table" iptables -t nat -F

    # Default policies
    apply_or_print "Default drop INPUT" iptables -P INPUT DROP
    apply_or_print "Default accept OUTPUT" iptables -P OUTPUT ACCEPT
    apply_or_print "Default accept FORWARD" iptables -P FORWARD DROP

    # Loopback
    apply_or_print "Allow loopback" iptables -A INPUT -i lo -j ACCEPT

    # Established connections
    apply_or_print "Allow established" iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # SSH (optional)
    if [[ "$ALLOW_SSH" == "yes" ]]; then
        apply_or_print "Allow SSH" iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    fi

    # Console port
    if [[ -n "$MANAGEMENT_NET" ]]; then
        apply_or_print "Allow console from mgmt net" iptables -A INPUT -p tcp -s "$MANAGEMENT_NET" --dport "$CONSOLE_PORT" -j ACCEPT
    else
        apply_or_print "Allow console (all)" iptables -A INPUT -p tcp --dport "$CONSOLE_PORT" -j ACCEPT
    fi

# --- Main ---
echo "=== MCP Server Firewall Setup ==="
echo ""
echo "Configuration:"
echo "  Console port:    $CONSOLE_PORT"
echo "  MCP HTTP port:   $MCP_HTTP_PORT"
echo "  Management net:  ${MANAGEMENT_NET:-"(not set, open to all)"}"
echo "  User net:        ${USER_NET:-"(not set, open to all)"}"
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
echo "  1. Verify: curl -m 5 http://<console-ip>:$CONSOLE_PORT/api/meta  (from allowed net)"
echo "  2. Verify: curl -m 5 http://<mcp-ip>:$MCP_HTTP_PORT/health        (from user net)"
echo "  3. Verify: access from unauthorized network is blocked"
echo "  4. Record results in Plane Issue P2-10"


    # MCP HTTP port
    if [[ -n "$USER_NET" ]]; then
        apply_or_print "Allow MCP HTTP from user net" iptables -A INPUT -p tcp -s "$USER_NET" --dport "$MCP_HTTP_PORT" -j ACCEPT
    else
        apply_or_print "Allow MCP HTTP (all)" iptables -A INPUT -p tcp --dport "$MCP_HTTP_PORT" -j ACCEPT
    fi

    # Log dropped packets (rate-limited)
    apply_or_print "Log dropped (rate-limit)" iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables-dropped: "

    # Save rules (Debian/Ubuntu)
    if command -v iptables-save &>/dev/null && [[ -d /etc/iptables ]]; then
        apply_or_print "Save iptables rules" bash -c "iptables-save > /etc/iptables/rules.v4"
    fi

    if $DRY_RUN; then
        echo ""
        echo "--- iptables rules that would be applied ---"
        iptables -L -n -v 2>/dev/null || true
    else
        iptables -L -n -v
    fi
}


if [[ -z "$MANAGEMENT_NET" || -z "$USER_NET" ]]; then
    log "WARNING: MANAGEMENT_NET or USER_NET not set."
    log "  Set environment variables to restrict access by source network."
    log "  Example: MANAGEMENT_NET=10.0.1.0/24 USER_NET=10.0.2.0/24"
    log ""
    log "  Without network restrictions, ports will be open to all sources."
    log "  Press Ctrl+C to cancel, or wait 10 seconds to continue..."
    sleep 10
fi
