@echo off
REM =====================================================================
REM Linux Remote Management MCP Server — 管理コンソール 起動スクリプト (Windows)
REM =====================================================================
REM
REM   管理コンソール          : http://127.0.0.1:8080/
REM   MCP HTTP は別プロセスで python -m app.mcp_http_entry を起動
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
echo   MCP HTTP      : 別ターミナルで python -m app.mcp_http_entry
echo.

REM ---- ポート使用中チェック ----
netstat -ano | findstr ":8080 " | findstr "LISTENING" >nul 2>&1
if %errorlevel% equ 0 (
    echo   [ERROR] ポート 8080 は既に使用されています。
    echo.
    echo   以下のコマンドで占用プロセスを確認できます:
    echo     netstat -ano ^| findstr ":8080"
    echo     tasklist ^| findstr "〈PID〉"
    echo.
    pause
    exit /b 1
)

echo   Ctrl+C で停止
echo ============================================
echo.

python -m app
