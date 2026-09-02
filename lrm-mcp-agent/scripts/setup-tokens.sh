#!/bin/bash
set -euo pipefail

# Token setup script for Linux Agent
# Prompts for raw tokens, generates SHA-256 hashes, and updates config.yml

CONFIG_DIR="/etc/lrm-mcp-agent"
CONFIG_FILE="$CONFIG_DIR/config.yml"

# Allow overriding config path for testing
if [ "${1:-}" != "" ]; then
    CONFIG_FILE="$1"
fi

echo "=== Linux Agent Token Setup ==="
echo ""

# Check if config exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: Config file not found: $CONFIG_FILE"
    echo "Run setup.sh first."
    exit 1
fi

# Check for required tools
if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 is required but not installed."
    exit 1
fi

if ! command -v sed &> /dev/null; then
    echo "ERROR: sed is required but not installed."
    exit 1
fi

echo "This script will help you set up authentication tokens."
echo "You will enter raw token values (passwords) for each token slot."
echo "The script will generate SHA-256 hashes and update the config."
echo ""
echo "NOTE: Raw tokens are NOT stored in the agent config."
echo "      Store them securely and register them in the MCP Server."
echo ""

# Function to generate SHA-256 hash
hash_token() {
    local token="$1"
    python3 -c "import hashlib; print(hashlib.sha256('$token'.encode()).hexdigest())"
}

# Function to prompt for token with confirmation
prompt_token() {
    local token_id="$1"
    local token_name="$2"
    local scope="$3"

    echo "--- Token: $token_id ($token_name, scope: $scope) ---"

    while true; do
        read -p "  Enter raw token for '$token_name' (scope: $scope, or press Enter to skip): " raw_token
        echo ""

        if [ -z "$raw_token" ]; then
            echo "  Skipped."
            echo ""
            return 1
        fi

        read -p "  Confirm raw token for '$token_name': " confirm_token
        echo ""

        if [ "$raw_token" != "$confirm_token" ]; then
            echo "  Tokens do not match. Try again."
            echo ""
            continue
        fi

        if [ ${#raw_token} -lt 16 ]; then
        echo "  WARNING: Token is less than 16 characters. Consider using a stronger token."
        fi

        HASH=$(hash_token "$raw_token")
        echo "  Generated hash: $HASH"
        echo ""

        # Store hash for later use
        echo "$HASH"
        return 0
    done
}

# Parse token entries from config.yml
# Find lines with "id:" under "tokens:" section
declare -a TOKEN_IDS=()
declare -a TOKEN_NAMES=()
declare -a TOKEN_SCOPES=()

in_tokens_section=false
while IFS= read -r line; do
    # Detect tokens section
    if echo "$line" | grep -q "^  tokens:"; then
        in_tokens_section=true
        continue
    fi

    # Exit tokens section when we hit another top-level key
    if $in_tokens_section && echo "$line" | grep -qE "^[a-z]"; then
        in_tokens_section=false
        continue
    fi

    if $in_tokens_section; then
        # Parse token id
        if echo "$line" | grep -qE '^\s+- id:'; then
            id=$(echo "$line" | sed 's/.*id: *"*\([^"]*\)"*/\1/')
            TOKEN_IDS+=("$id")
        fi
        # Parse token name
        if echo "$line" | grep -qE '^\s+name:'; then
            name=$(echo "$line" | sed 's/.*name: *"*\([^"]*\)"*/\1/')
            TOKEN_NAMES+=("$name")
        fi
        # Parse token scope
        if echo "$line" | grep -qE '^\s+scope:'; then
            scope=$(echo "$line" | sed 's/.*scope: *//')
            TOKEN_SCOPES+=("$scope")
        fi
    fi
done < "$CONFIG_FILE"

if [ ${#TOKEN_IDS[@]} -eq 0 ]; then
    echo "No token entries found in config."
    exit 0
fi

echo "Found ${#TOKEN_IDS[@]} token slot(s) in config."
echo ""

# Collect hashes
declare -a HASHES=()
for i in "${!TOKEN_IDS[@]}"; do
    result=$(prompt_token "${TOKEN_IDS[$i]}" "${TOKEN_NAMES[$i]}" "${TOKEN_SCOPES[$i]}")
    hash=$(echo "$result" | grep -E '^[a-f0-9]{64}$')

    if [ -n "$hash" ] && [ ${#hash} -eq 64 ]; then
        HASHES+=("$hash")
    else
        HASHES+=("")
    fi
done

# Update config.yml with hashes
echo "Updating $CONFIG_FILE..."

# Create backup
cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
echo "Backup saved to ${CONFIG_FILE}.bak"

# Replace empty hash fields
hash_index=0
while IFS= read -r line; do
    if echo "$line" | grep -qE '^\s+hash:\s*""'; then
        if [ $hash_index -lt ${#HASHES[@]} ] && [ -n "${HASHES[$hash_index]}" ]; then
            # Replace empty hash with generated hash
            echo "$line" | sed "s|hash: \"\"|hash: \"${HASHES[$hash_index]}\"|"
        else
            echo "$line"
        fi
        hash_index=$((hash_index + 1))
    else
        echo "$line"
    fi
done < "$CONFIG_FILE" > "${CONFIG_FILE}.tmp"

mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"

# Set proper permissions
chmod 600 "$CONFIG_FILE"

echo ""
echo "=== Token setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Review the updated config: $CONFIG_FILE"
echo "  2. Start the agent: systemctl start lrm-mcp-agent"
echo "  3. Check status: systemctl status lrm-mcp-agent"
echo ""
echo "IMPORTANT: Register the raw tokens in the MCP Server to enable authentication."