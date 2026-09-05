"""MCP server (stdio transport) エントリポイント。

Claude Desktop / Codex 等のAIクライアントからは stdio で起動する。

claude_desktop_config.json の例:
    {
      "mcpServers": {
        "linux-remote-management": {
          "command": "python -m app.mcp_entry",
          "cwd": "/path/to/mcp-server"
        }
      }
    }
"""
from __future__ import annotations

import logging
import os

from .approvals import ApprovalStore
from .auth import authenticate_raw_token, reset_current_token, set_current_token
from .config import load_config
from .db import TokenStore
from .mcp_audit import McpAudit
from .mcp_server import build_mcp


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    config = load_config()
    store = TokenStore(config.data_dir / "tokens.db")
    raw_token = os.environ.get(config.mcp.stdio_token_env, "")
    token = authenticate_raw_token(store, raw_token)
    if token is None:
      raise RuntimeError(
        f"stdio MCP credential is missing or invalid; set {config.mcp.stdio_token_env}"
      )
    approvals = None
    if config.console.require_approval:
        try:
            approvals = ApprovalStore(config.data_dir / "approvals.db")
        except Exception as exc:  # noqa: BLE001
            logging.warning("ApprovalStore 初期化に失敗: %s", exc)
    audit = McpAudit(config.data_dir / "mcp_audit.log") if config.console.mcp_audit else None
    mcp = build_mcp(config, store, approvals=approvals, audit=audit)
    context = set_current_token(token)
    try:
      store.touch_last_used(token.id)
      mcp.run()
    finally:
      reset_current_token(context)


if __name__ == "__main__":
    main()
