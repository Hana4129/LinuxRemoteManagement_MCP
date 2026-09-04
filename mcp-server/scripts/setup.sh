#!/bin/bash
set -euo pipefail

# MCP Server setup script
# Creates virtual environment, installs dependencies, prepares data directory

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DATA_DIR="${PROJECT_DIR}/data"
VENV_DIR="${PROJECT_DIR}/.venv"

echo "=== MCP Server Setup ==="
echo ""

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 is required but not installed."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "Python version: $PYTHON_VERSION"

# Create data directory
mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"
echo "Data directory: $DATA_DIR"

# Create virtual environment
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    echo "Created virtual environment: $VENV_DIR"
else
    echo "Virtual environment already exists: $VENV_DIR"
fi

# Activate virtual environment
source "${VENV_DIR}/bin/activate"

# Upgrade pip
pip install --upgrade pip setuptools wheel

# Install dependencies
pip install -r "${PROJECT_DIR}/requirements.txt"
echo "Installed dependencies from requirements.txt"

# Deactivate virtual environment
deactivate

# Create setup completion marker
touch "${VENV_DIR}/.setup_complete"

echo ""
echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Review config: ${PROJECT_DIR}/config.yml"
echo "  2. Set up tokens: sudo ${SCRIPT_DIR}/setup-tokens.sh"
echo "  3. Start server: source ${VENV_DIR}/bin/activate && python -m app"
echo ""
echo "Or use the launcher script:"
echo "  ./start_server.sh"
