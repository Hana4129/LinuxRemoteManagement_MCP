"""監査ログのハッシュチェーン検証 CLI。

使い方:
    python -m app.verify_audit_log <パス> [<パス> ...]

各ログファイルの ``prev_hash`` / ``hash`` チェーンを検証し、
改ざん・破綻があれば終了コード 1、すべて正常なら 0 を返す。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .mcp_audit import verify_audit_log


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="app.verify_audit_log",
        description="MCP Server 監査ログ (JSONL) のハッシュチェーンを検証する",
    )
    parser.add_argument("paths", nargs="+", type=Path, metavar="PATH", help="監査ログファイル")
    args = parser.parse_args(argv)

    failed = 0
    for path in args.paths:
        problems = verify_audit_log(path)
        if problems:
            failed = 1
            print(f"FAIL: {path}")
            for msg in problems:
                print(f"  - {msg}")
        else:
            print(f"OK: {path}")
    return failed


if __name__ == "__main__":
    sys.exit(main())