"""管理コンソール (FastAPI Webサーバー)。"""

from __future__ import annotations

import sys
from pathlib import Path

# mcp-server/ を sys.path に追加して from app.* を解決する
_MCP_SERVER = Path(__file__).resolve().parent.parent / "mcp-server"
if str(_MCP_SERVER) not in sys.path:
    sys.path.insert(0, str(_MCP_SERVER))

__version__ = "0.1.0"
