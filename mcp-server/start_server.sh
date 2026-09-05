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
VENV_DIR="${SCRIPT_DIR}/.venv"
SETUP_MARKER="${VENV_DIR}/.setup_complete"

echo ""
echo "============================================"
echo "  Linux Remote Management MCP Server"
echo "============================================"
echo ""

# ---- セットアップ完了チェック ----
# .venv は git 管理外のため、初回起動時 (または必要時) に自動構築する
setup_needed=false

if [ ! -d "$VENV_DIR" ]; then
    echo "  [INFO] 仮想環境が見つかりません。セットアップが必要です。"
    setup_needed=true
elif [ ! -f "$SETUP_MARKER" ]; then
    echo "  [INFO] セットアップが完了していません。セットアップを実行します。"
    setup_needed=true
elif [ ! -f "${VENV_DIR}/bin/python" ] && [ ! -f "${VENV_DIR}/Scripts/python.exe" ]; then
    echo "  [INFO] 仮想環境が破損しています。再セットアップします。"
    setup_needed=true
elif [ -f "${SCRIPT_DIR}/requirements.txt" ] && [ "${SCRIPT_DIR}/requirements.txt" -nt "$SETUP_MARKER" ]; then
    echo "  [INFO] requirements.txt が更新されています。依存関係を再インストールします。"
    setup_needed=true
fi

if [ "$setup_needed" = true ]; then
    echo ""
    echo "  セットアップを実行中..."
    echo ""
    bash "${SCRIPT_DIR}/scripts/setup.sh"
    echo ""
fi

# ---- 仮想環境の Python を解決 (Linux/macOS: bin/, Windows Git Bash: Scripts/) ----
if [ -f "${VENV_DIR}/bin/python" ]; then
    PYTHON_BIN="${VENV_DIR}/bin/python"
elif [ -f "${VENV_DIR}/Scripts/python.exe" ]; then
    PYTHON_BIN="${VENV_DIR}/Scripts/python.exe"
else
    echo "  [ERROR] 仮想環境のPythonが見つかりません。"
    echo "  手動でセットアップを実行してください: ./scripts/setup.sh"
    exit 1
fi

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
elif command -v netstat >/dev/null 2>&1; then
    # Windows Git Bash 等 (lsof/ss が無い環境)。netstat -an は Windows/Linux/macOS 共通で利用可能
    if netstat -an 2>/dev/null | grep -E "[:.]${PORT}[[:space:]]" | grep -qi "listen"; then
        echo "  [ERROR] ポート ${PORT} は既に使用されています。"
        echo ""
        echo "  以下のコマンドで占用プロセスを確認できます (Windows):"
        echo "    netstat -ano | findstr \":${PORT}\""
        echo "    tasklist | findstr \"<PID>\""
        echo ""
        exit 1
    fi
fi

echo "  管理コンソール : http://127.0.0.1:${PORT}/"
echo "  MCP endpoint  : http://127.0.0.1:${PORT}/mcp"
echo ""
echo "  Ctrl+C で停止"
echo "============================================"
echo ""

exec "$PYTHON_BIN" -m app
