@echo off
REM =====================================================================
REM Linux Remote Management MCP Server — 管理コンソール 起動スクリプト (Windows)
REM =====================================================================
REM
REM   HTTP API (管理コンソール) : http://127.0.0.1:8080/
REM   MCP (streamable HTTP)    : http://127.0.0.1:8080/mcp
REM
REM   設定ファイル: config.yml (同ディレクトリ)
REM   データ保存  : data/ (tokens.db, approvals.db, mcp_audit.log)
REM =====================================================================

cd /d "%~dp0"

echo.
echo ============================================
echo   Linux Remote Management MCP Server
echo ============================================
echo.
echo   管理コンソール : http://127.0.0.1:8080/
echo   MCP endpoint  : http://127.0.0.1:8080/mcp
echo.
echo   Ctrl+C で停止
echo ============================================
echo.

python -m app
