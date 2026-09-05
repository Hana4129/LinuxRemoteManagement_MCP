#!/bin/bash
set -euo pipefail

# MCP Server setup script
# Creates virtual environment, installs dependencies, prepares data directory
# Works on Linux/macOS (venv layout: bin/) and Windows Git Bash (venv layout: Scripts/)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DATA_DIR="${PROJECT_DIR}/data"
VENV_DIR="${PROJECT_DIR}/.venv"

echo "=== MCP Server Setup ==="
echo ""

# Check Python (python3, falling back to python — Windows often lacks python3)
if command -v python3 &> /dev/null; then
    PYTHON_BIN="python3"
elif command -v python &> /dev/null; then
    PYTHON_BIN="python"
else
    echo "ERROR: python3 is required but not installed."
    exit 1
fi

PYTHON_VERSION=$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "Python version: $PYTHON_VERSION"

# Create data directory
mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR" 2>/dev/null || true
echo "Data directory: $DATA_DIR"

# Create virtual environment
if [ ! -d "$VENV_DIR" ]; then
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    echo "Created virtual environment: $VENV_DIR"
else
    echo "Virtual environment already exists: $VENV_DIR"
fi

# Resolve the venv python (Linux/macOS: bin/python, Windows: Scripts/python.exe)
if [ -f "${VENV_DIR}/bin/python" ]; then
    VENV_PYTHON="${VENV_DIR}/bin/python"
elif [ -f "${VENV_DIR}/Scripts/python.exe" ]; then
    VENV_PYTHON="${VENV_DIR}/Scripts/python.exe"
else
    echo "ERROR: virtual environment python not found in ${VENV_DIR}"
    exit 1
fi

# Install dependencies using the venv python directly (no activation required)
"$VENV_PYTHON" -m pip install --upgrade pip setuptools wheel
"$VENV_PYTHON" -m pip install -r "${PROJECT_DIR}/requirements.txt"
echo "Installed dependencies from requirements.txt"

# Create setup completion marker
touch "${VENV_DIR}/.setup_complete"

echo ""
echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Review config: ${PROJECT_DIR}/config.yml"
echo "  2. Set up tokens: ${SCRIPT_DIR}/setup-tokens.sh"
echo "  3. Start server: ./start_server.sh"
