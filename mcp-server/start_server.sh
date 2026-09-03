#!/usr/bin/env bash
# =====================================================================
# Linux Remote Management MCP Server — 管理コンソール 起動スクリプト
# =====================================================================
#
#   HTTP API (管理コンソール) : http://127.0.0.1:8080/
#   MCP (streamable HTTP)    : http://127.0.0.1:8080/mcp
#
#   設定ファイル: config.yml (同ディレクトリ)
#   データ保存  : data/ (tokens.db, approvals.db, mcp_audit.log)
# =====================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "============================================"
echo "  Linux Remote Management MCP Server"
echo "============================================"
echo ""
echo "  管理コンソール : http://127.0.0.1:8080/"
echo "  MCP endpoint  : http://127.0.0.1:8080/mcp"
echo ""
echo "  Ctrl+C で停止"
echo "============================================"
echo ""

exec python -m app
