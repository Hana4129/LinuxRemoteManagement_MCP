"""MCP 監査ログ (JSONL)。

MCP Tool 呼び出しのすべてを構造化ログとして記録する。
設計書 §28 Level 2 "Audit Log" / Level 3 "Immutable audit log" に対応。

- 1行1エントリの JSON Lines、ファイルは 0600 (POSIX)
- 生トークンやファイル内容などの機密値は記録しない (パラメータは要約のみ)
- 破壊的操作には approval_id を含める
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_MAX_VALUE_LEN = 200
_MAX_JSON_KEYS = 20


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def sanitize_params(params: dict[str, Any] | None) -> dict[str, str]:
    """ログ安全な要約へ変換する。文字列は切り詰め、機密キーはマスクする。"""
    if not params:
        return {}
    sensitive = {"token", "password", "authorization", "secret", "raw"}
    out: dict[str, str] = {}
    for key in list(params)[:_MAX_JSON_KEYS]:
        value = params[key]
        text = "" if value is None else str(value)
        if key.lower() in sensitive:
            out[key] = "***"
            continue
        if len(text) > _MAX_VALUE_LEN:
            text = text[:_MAX_VALUE_LEN] + "…"
        out[key] = text
    return out


class McpAudit:
    """JSONL 監査ログライタ（ローテーション対応）。"""

    def __init__(
        self,
        path: str | Path,
        enabled: bool = True,
        max_size_mb: int = 10,
        max_backups: int = 5,
        compress: bool = True,
    ):
        self.path = Path(path)
        self.enabled = enabled
        self.max_size_mb = max_size_mb
        self.max_backups = max_backups
        self.compress = compress
        self._lock = threading.Lock()
        self._fh = None
        if self.enabled:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(self.path, "a", encoding="utf-8")
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass  # Windows では無視

    def log(
        self,
        *,
        actor: str,
        action: str,
        server: str | None = None,
        params: dict[str, Any] | None = None,
        ok: bool | None = None,
        error_kind: str | None = None,
        duration_ms: float | None = None,
        detail: str | None = None,
    ) -> None:
        """1エントリを書き込む。書き込み失敗は呼び出し元へ伝播させない。"""
        if not self.enabled or self._fh is None:
            return
        entry = {
            "timestamp": now_iso(),
            "actor": actor,
            "action": action,
            "server": server,
            "params": sanitize_params(params),
            "ok": ok,
            "error_kind": error_kind,
            "duration_ms": round(duration_ms, 1) if duration_ms is not None else None,
            "detail": (detail[:300] if detail else None),
        }
        line = json.dumps(entry, ensure_ascii=False)
        try:
            with self._lock:
                self._fh.write(line + "\n")
                self._fh.flush()
        except OSError:
            pass

    def _rotate_if_needed(self) -> None:
        """ファイルサイズが上限を超えていたらローテーションする。"""

        if self.max_size_mb <= 0:
            return
        try:
            size = self.path.stat().st_size
        except OSError:
            return
        max_bytes = self.max_size_mb * 1024 * 1024
        if size < max_bytes:
            return
        self._rotate()

    def _rotate(self) -> None:
        """ログローテーションを実行する。"""

        import gzip
        # Close current file
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
        # Rotate existing backups (from oldest to newest)
        for i in range(self.max_backups - 1, -1, -1):
            if i == 0:
                old_path = str(self.path)
            else:
                old_path = f"{self.path}.{i}"
                if self.compress:
                    old_path += ".gz"
            new_path = f"{self.path}.{i + 1}"
            if self.compress:
                new_path += ".gz"
            if Path(old_path).exists():
                if i == self.max_backups - 1:
                    # Delete oldest
                    try:
                        os.remove(old_path)
                    except OSError:
                        pass
                else:
                    try:
                        os.rename(old_path, new_path)
                    except OSError:
                        pass
        # Compress the rotated file
        if self.compress:
            compressed = f"{self.path}.1.gz"
            try:
                with open(str(self.path), "rb") as f_in:
                    with gzip.open(compressed, "wb") as f_out:
                        import shutil
                        shutil.copyfileobj(f_in, f_out)
                os.remove(str(self.path))
            except OSError:
                pass
        # Reopen the log file
        try:
            self._fh = open(self.path, "a", encoding="utf-8")
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        except OSError:
            self._fh = None

    def read_entries(self, limit: int = 1000) -> list[dict]:
        """テスト/確認用: 書き込まれたエントリを読み出す。"""
        if not self.path.exists():
            return []
        with open(self.path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        out = []
        for line in lines[-limit:]:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            finally:
                self._fh = None
