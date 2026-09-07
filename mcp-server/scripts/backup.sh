#!/bin/bash
set -euo pipefail

# MCP Server Backup Script
# Backs up config.yml, tokens database, and audit logs.
#
# Usage:
#   ./scripts/backup.sh                  # backup to ./backups/
#   ./scripts/backup.sh /mnt/backup/mcp  # backup to custom directory
#   ./scripts/backup.sh --dry-run        # show what would be backed up

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${1:-${PROJECT_DIR}/backups}"
DRY_RUN=false

if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
    BACKUP_DIR="${PROJECT_DIR}/backups"
fi

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_PATH="${BACKUP_DIR}/${TIMESTAMP}"

log() { echo "[backup] $*"; }

echo "=== MCP Server Backup ==="
echo ""
echo "Source: ${PROJECT_DIR}"
echo "Destination: ${BACKUP_PATH}"
echo "Dry run: ${DRY_RUN}"
echo ""

if $DRY_RUN; then
    log "Files that would be backed up:"
    echo "  - config.yml"
    echo "  - data/tokens.db"
    echo "  - data/mcp_audit.log"
    echo "  - data/mcp_audit.log.*.gz"
    echo ""
    log "To execute: $0 ${1:-}"
    exit 0
fi

# Create backup directory
mkdir -p "$BACKUP_PATH"
chmod 700 "$BACKUP_PATH"

# Backup config
if [[ -f "${PROJECT_DIR}/config.yml" ]]; then
    cp -p "${PROJECT_DIR}/config.yml" "${BACKUP_PATH}/config.yml"
    log "Backed up: config.yml"
fi

# Backup data directory
if [[ -d "${PROJECT_DIR}/data" ]]; then
    mkdir -p "${BACKUP_PATH}/data"
    # tokens.db
    if [[ -f "${PROJECT_DIR}/data/tokens.db" ]]; then
        cp -p "${PROJECT_DIR}/data/tokens.db" "${BACKUP_PATH}/data/tokens.db"
        log "Backed up: data/tokens.db"
    fi
    # audit logs
    if ls "${PROJECT_DIR}/data"/mcp_audit.log* 1>/dev/null 2>&1; then
        cp -p "${PROJECT_DIR}/data"/mcp_audit.log* "${BACKUP_PATH}/data/"
        log "Backed up: data/mcp_audit.log*"
    fi
fi

# Create manifest
{
    echo "timestamp: ${TIMESTAMP}"
    echo "hostname: $(hostname)"
    echo "user: $(whoami)"
    echo "files:"
    find "$BACKUP_PATH" -type f | sed "s|${BACKUP_PATH}/|  - |"
} > "${BACKUP_PATH}/MANIFEST.txt"
log "Created: MANIFEST.txt"

# Compress
cd "$BACKUP_DIR"
tar czf "${TIMESTAMP}.tar.gz" "$TIMESTAMP"
rm -rf "$BACKUP_PATH"
log "Compressed: ${BACKUP_DIR}/${TIMESTAMP}.tar.gz"

# Retention: keep last 7 backups
ls -1t "${BACKUP_DIR}"/*.tar.gz 2>/dev/null | tail -n +8 | xargs -r rm -f
log "Retention: kept last 7 backups"

echo ""
echo "=== Backup complete ==="
echo "Archive: ${BACKUP_DIR}/${TIMESTAMP}.tar.gz"
echo ""
echo "To restore:"
echo "  tar xzf ${BACKUP_DIR}/${TIMESTAMP}.tar.gz -C ${BACKUP_DIR}/"
echo "  cp ${BACKUP_DIR}/${TIMESTAMP}/config.yml ${PROJECT_DIR}/"
echo "  cp ${BACKUP_DIR}/${TIMESTAMP}/data/* ${PROJECT_DIR}/data/"
