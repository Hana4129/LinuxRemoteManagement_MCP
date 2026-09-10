"""MCP streamable HTTP専用サーバーの起動エントリポイント。"""

from __future__ import annotations

import logging

import uvicorn

from .config import load_config
from .config_reload import setup_config_reload
from .mcp_http import create_mcp_http_app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    config = load_config()
    if not config.mcp.enabled:
        raise RuntimeError("mcp.enabled=false のためMCP HTTPサーバーを起動できません")
    # ホットリロード初期化
    setup_config_reload(config)
    app = create_mcp_http_app(config)
    uvicorn.run(app, host=config.mcp.host, port=config.mcp.port, log_level="info")


if __name__ == "__main__":
    main()