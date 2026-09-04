#!/bin/bash
set -euo pipefail

# Token setup script for MCP Server
# Creates initial API tokens and stores them in the SQLite database

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DATA_DIR="${PROJECT_DIR}/data"
DB_PATH="${DATA_DIR}/tokens.db"
VENV_DIR="${PROJECT_DIR}/.venv"

echo "=== MCP Server Token Setup ==="
echo ""

# Check Python availability
if [ -d "$VENV_DIR" ]; then
    source "${VENV_DIR}/bin/activate"
    PYTHON="python"
else
    PYTHON="python3"
fi

# Check if config exists
CONFIG_FILE="${PROJECT_DIR}/config.yml"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: Config file not found: $CONFIG_FILE"
    echo "Run setup.sh first."
    exit 1
fi

# Create data directory if needed
mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"

echo "This script will help you create initial API tokens."
echo "Tokens are used by agents to authenticate with the MCP Server."
echo ""
echo "WARNING: Generated tokens will be displayed ONCE. Store them securely!"
echo ""

# Function to prompt for token details
prompt_token() {
    local token_name="$1"
    local server_ids="$2"
    local scope="$3"

    echo "--- Token: $token_name ---"
    echo "  Servers: $server_ids"
    echo "  Scope: $scope"
    echo ""

    while true; do
        read -p "  Create this token? [Y/n]: " confirm
        confirm=${confirm:-Y}

        case "$confirm" in
            [Yy]*)
                return 0
                ;;
            [Nn]*)
                echo "  Skipped."
                echo ""
                return 1
                ;;
            *)
                echo "  Please answer Y or n."
                ;;
        esac
    done
}

# Default token configurations
declare -a TOKEN_NAMES=("dev-token" "prod-token")
declare -a TOKEN_SERVERS=("dev-web-01,dev-db-01" "ubuntu-server1,prod-web-01,stg-batch-01")
declare -a TOKEN_SCOPES=("read,write" "read,write")

echo "Found ${#TOKEN_NAMES[@]} default token configuration(s)."
echo ""

# Collect user choices
declare -a CREATE_TOKENS=()
for i in "${!TOKEN_NAMES[@]}"; do
    if prompt_token "${TOKEN_NAMES[$i]}" "${TOKEN_SERVERS[$i]}" "${TOKEN_SCOPES[$i]}"; then
        CREATE_TOKENS+=("$i")
    fi
done

if [ ${#CREATE_TOKENS[@]} -eq 0 ]; then
    echo "No tokens to create. Exiting."
    exit 0
fi

echo ""
echo "Creating tokens..."
echo ""

# Create temporary Python script
TEMP_SCRIPT=$(mktemp)
trap "rm -f $TEMP_SCRIPT" EXIT

cat > "$TEMP_SCRIPT" << 'PYEOF'
import sys
import json
import os

project_dir = os.environ.get('MCP_PROJECT_DIR', '')
if project_dir:
    sys.path.insert(0, project_dir)

from app.db import TokenStore
from app.config import load_config

config = load_config()
db_path = os.environ.get('MCP_DB_PATH', '')
store = TokenStore(db_path)

tokens_json = os.environ.get('MCP_TOKENS', '[]')
tokens = json.loads(tokens_json)

for tok in tokens:
    record, raw = store.create_token(
        name=tok['name'],
        server_ids=tok['server_ids'],
        scope=tok['scope'],
    )
    print(f"  Created: {record.name} (prefix: {record.prefix})")
    print(f"    Token: {raw}")
    print()

print("=" * 60)
print("IMPORTANT: Save these tokens securely!")
print("They cannot be retrieved again (only hashes are stored).")
print("=" * 60)
print()
print("Register these tokens in the agent config.yml files.")
print()
PYEOF

# Build tokens JSON
TOKENS_JSON="["
first=true
for i in "${CREATE_TOKENS[@]}"; do
    if [ "$first" = true ]; then
        first=false
    else
        TOKENS_JSON+=","
    fi
    TOKENS_JSON+="{\"name\":\"${TOKEN_NAMES[$i]}\",\"server_ids\":[\"$(echo "${TOKEN_SERVERS[$i]}" | sed 's/,/","/g')\"],\"scope\":\"${TOKEN_SCOPES[$i]}\"}"
done
TOKENS_JSON+="]"

# Execute with environment variables
MCP_PROJECT_DIR="$PROJECT_DIR" MCP_DB_PATH="$DB_PATH" MCP_TOKENS="$TOKENS_JSON" $PYTHON "$TEMP_SCRIPT"

echo ""
echo "=== Token setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Copy the tokens above to your agent config.yml files"
echo "  2. Start the MCP Server: source ${VENV_DIR}/bin/activate && python -m app"
echo ""
