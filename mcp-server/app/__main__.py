"""管理コンソール (FastAPI + uvicorn) の起動エントリポイント。

    python -m app              # 管理コンソール (専用Webサーバー)
    python -m app.mcp_entry    # MCP (stdio)
    python -m app.mcp_http_entry  # MCP (HTTP, 別Webサーバー)
    python -m tools.mock_agent --port 8443   # 開発用モックAgent
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

import uvicorn

# リポジトリルートを sys.path に追加して from console.* を解決する
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.config import load_config
from console.main import create_app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    config = load_config()
    app = create_app(config)
    uvicorn.run(app, host=config.console.host, port=config.console.port, log_level="info")


if __name__ == "__main__":
    main()
