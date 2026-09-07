#!/bin/bash
set -euo pipefail

# MCP Server Monitoring Script
# Performs health checks and reports status.
# Designed to be run from cron or a monitoring system (Nagios/Zabbix compatible).
#
# Usage:
#   ./scripts/monitor.sh                # human-readable output
#   ./scripts/monitor.sh --nagios       # Nagios-compatible output with exit codes
#   ./scripts/monitor.sh --json         # JSON output
#
# Nagios exit codes: 0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONSOLE_URL="${CONSOLE_URL:-http://127.0.0.1:8080}"
MCP_URL="${MCP_URL:-http://127.0.0.1:8090}"
DATA_DIR="${PROJECT_DIR}/data"
FORMAT="human"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --nagios) FORMAT="nagios" ;;
        --json) FORMAT="json" ;;
        -h|--help)
            echo "Usage: $0 [--nagios|--json]"
            echo ""
            echo "Health check script for MCP Server."
            echo "  --nagios    Nagios-compatible output"
            echo "  --json      JSON output"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

EXIT_OK=0
EXIT_WARN=1
EXIT_CRIT=2
EXIT_UNKNOWN=3
exit_code=$EXIT_OK
warnings=()
criticals=()

# --- Check: Console health ---
check_console() {
    local http_code
    http_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "${CONSOLE_URL}/api/meta" 2>/dev/null || echo "000")"
    if [[ "$http_code" == "200" ]]; then
        echo "console: OK (HTTP $http_code)"
    elif [[ "$http_code" == "000" ]]; then
        criticals+=("console: UNREACHABLE")
        exit_code=$EXIT_CRIT
    else
        warnings+=("console: HTTP $http_code")
        [[ $exit_code -lt $EXIT_CRIT ]] && exit_code=$EXIT_WARN
    fi
}

# --- Check: MCP HTTP health ---
check_mcp_http() {
    local http_code
    http_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "${MCP_URL}/health" 2>/dev/null || echo "000")"
    if [[ "$http_code" == "200" ]]; then
        echo "mcp_http: OK (HTTP $http_code)"
    elif [[ "$http_code" == "000" ]]; then
        criticals+=("mcp_http: UNREACHABLE")
        exit_code=$EXIT_CRIT
    else
        warnings+=("mcp_http: HTTP $http_code")
        [[ $exit_code -lt $EXIT_CRIT ]] && exit_code=$EXIT_WARN
    fi
}

# --- Check: Disk space ---
check_disk() {
    local usage
    usage="$(df "$DATA_DIR" | awk 'NR==2 {print $5}' | tr -d '%')"
    if [[ "$usage" -gt 90 ]]; then
        criticals+=("disk: ${usage}% used")
        exit_code=$EXIT_CRIT
    elif [[ "$usage" -gt 80 ]]; then
        warnings+=("disk: ${usage}% used")
        [[ $exit_code -lt $EXIT_CRIT ]] && exit_code=$EXIT_WARN
    else
        echo "disk: OK (${usage}% used)"
    fi
}

# --- Check: Audit log integrity ---
check_audit_log() {
    if [[ -f "${DATA_DIR}/mcp_audit.log" ]]; then
        local perms
        perms="$(stat -c '%a' "${DATA_DIR}/mcp_audit.log" 2>/dev/null || echo "unknown")"
        if [[ "$perms" == "600" || "$perms" == "640" || "$perms" == "644" ]]; then
            echo "audit_log: OK (perms: $perms)"
        else
            warnings+=("audit_log: perms $perms (expected 600/640/644)")
            [[ $exit_code -lt $EXIT_CRIT ]] && exit_code=$EXIT_WARN
        fi
    else
        warnings+=("audit_log: not found")
        [[ $exit_code -lt $EXIT_CRIT ]] && exit_code=$EXIT_WARN
    fi
}

# --- Check: tokens.db exists ---
check_db() {
    if [[ -f "${DATA_DIR}/tokens.db" ]]; then
        echo "database: OK"
    else
        criticals+=("database: tokens.db not found")
        exit_code=$EXIT_CRIT
    fi
}

# --- Run checks ---
check_console
check_mcp_http
check_disk
check_audit_log
check_db

# --- Output ---
case "$FORMAT" in
    human)
        echo ""
        for w in "${warnings[@]}"; do echo "WARNING: $w"; done
        for c in "${criticals[@]}"; do echo "CRITICAL: $c"; done
        if [[ $exit_code -eq 0 ]]; then
            echo "Overall: OK"
        elif [[ $exit_code -eq 1 ]]; then
            echo "Overall: WARNING"
        else
            echo "Overall: CRITICAL"
        fi
        ;;
    nagios)
        if [[ $exit_code -eq 0 ]]; then
            echo "MCP_SERVER OK - all checks passed"
        elif [[ $exit_code -eq 1 ]]; then
            echo "MCP_SERVER WARNING - ${warnings[*]}"
        else
            echo "MCP_SERVER CRITICAL - ${criticals[*]}"
        fi
        ;;
    json)
        echo "{"
        echo "  \"status\": \"$([ $exit_code -eq 0 ] && echo "ok" || [ $exit_code -eq 1 ] && echo "warning" || echo "critical")\","
        echo "  \"exit_code\": $exit_code,"
        echo "  \"warnings\": [$(printf '"%s",' "${warnings[@]}" | sed 's/,$//')],"
        echo "  \"criticals\": [$(printf '"%s",' "${criticals[@]}" | sed 's/,$//')]"
        echo "}"
        ;;
esac

exit $exit_code
