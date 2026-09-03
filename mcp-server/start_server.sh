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

PORT=8080

echo ""
echo "============================================"
echo "  Linux Remote Management MCP Server"
echo "============================================"
echo ""
echo "  管理コンソール : http://127.0.0.1:${PORT}/"
echo "  MCP endpoint  : http://127.0.0.1:${PORT}/mcp"
echo ""

# ---- ポート使用中チェック ----
if command -v lsof >/dev/null 2>&1; then
    PORT_PID=$(lsof -ti tcp:${PORT} 2>/dev/null || true)
    if [ -n "$PORT_PID" ]; then
        echo "  [ERROR] ポート ${PORT} は既に使用されています (PID: ${PORT_PID})。"
        echo ""
        echo "  以下のコマンドで占用プロセスを確認できます:"
        echo "    lsof -i tcp:${PORT}"
        echo "    ps -p ${PORT_PID}"
        echo ""
        exit 1
    fi
elif command -v ss >/dev/null 2>&1; then
    if ss -tlnp 2>/dev/null | grep -q ":${PORT} "; then
        echo "  [ERROR] ポート ${PORT} は既に使用されています。"
        echo ""
        echo "  以下のコマンドで占用プロセスを確認できます:"
        echo "    ss -tlnp | grep :${PORT}"
        echo ""
        exit 1
    fi
fi

echo "  Ctrl+C で停止"
echo "============================================"
echo ""

exec python -m app
