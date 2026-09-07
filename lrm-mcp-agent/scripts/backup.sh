#!/bin/bash
set -euo pipefail

# Linux Agent Backup Script
# Backs up Agent config, data, and audit logs.
#
# Usage:
#   sudo ./scripts/backup.sh                  # backup to /var/backups/lrm-mcp-agent/
#   sudo ./scripts/backup.sh /mnt/backup      # backup to custom directory
#   sudo ./scripts/backup.sh --dry-run        # show what would be backed up

BACKUP_DIR="${1:-/var/backups/lrm-mcp-agent}"
DRY_RUN=false

if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
    BACKUP_DIR="/var/backups/lrm-mcp-agent"
fi

CONFIG_DIR="/etc/lrm-mcp-agent"
DATA_DIR="/var/lib/lrm-mcp-agent"
LOG_DIR="/var/log/lrm-mcp-agent"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_PATH="${BACKUP_DIR}/${TIMESTAMP}"

log() { echo "[backup] $*"; }

echo "=== Linux Agent Backup ==="
echo ""
echo "Sources:"
echo "  Config: ${CONFIG_DIR}"
echo "  Data:   ${DATA_DIR}"
echo "  Logs:   ${LOG_DIR}"
echo "Destination: ${BACKUP_PATH}"
echo "Dry run: ${DRY_RUN}"
echo ""

if $DRY_RUN; then
    log "Files that would be backed up:"
    echo "  - ${CONFIG_DIR}/config.yml"
    echo "  - ${DATA_DIR}/*"
    echo "  - ${LOG_DIR}/*.log"
    echo "  - ${LOG_DIR}/*.log.*.gz"
    echo ""
    log "To execute: $0 ${1:-}"
    exit 0
fi

# Create backup directory
mkdir -p "$BACKUP_PATH"
chmod 700 "$BACKUP_PATH"

# Backup config
if [[ -d "$CONFIG_DIR" ]]; then
    cp -rp "$CONFIG_DIR" "${BACKUP_PATH}/config"
    log "Backed up: config/"
fi

# Backup data
if [[ -d "$DATA_DIR" ]]; then
    mkdir -p "${BACKUP_PATH}/data"
    if ls "$DATA_DIR"/* 1>/dev/null 2>&1; then
        cp -rp "$DATA_DIR"/* "${BACKUP_PATH}/data/"
        log "Backed up: data/"
    fi
fi

# Backup logs
if [[ -d "$LOG_DIR" ]]; then
    mkdir -p "${BACKUP_PATH}/logs"
    if ls "$LOG_DIR"/*.log* 1>/dev/null 2>&1; then
        cp -rp "$LOG_DIR"/*.log* "${BACKUP_PATH}/logs/"
        log "Backed up: logs/"
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
echo "  sudo cp -r ${BACKUP_DIR}/${TIMESTAMP}/config/* ${CONFIG_DIR}/"
echo "  sudo cp -r ${BACKUP_DIR}/${TIMESTAMP}/data/* ${DATA_DIR}/"
