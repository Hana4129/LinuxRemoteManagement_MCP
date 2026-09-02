"""管理コンソール (FastAPI + uvicorn) の起動エントリポイント。

    python -m app          # コンソール
    python -m app.mcp_entry     # MCP (stdio)
    python -m app.mcp_http_entry   # MCP (HTTP, 別プロセス)
    python -m tools.mock_agent --port 8443   # 開発用モックAgent
"""
from __future__ import annotations

import logging

import uvicorn

from .config import load_config
from .main import create_app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    config = load_config()
    app = create_app(config)
    uvicorn.run(app, host=config.console.host, port=config.console.port, log_level="info")


if __name__ == "__main__":
    main()
