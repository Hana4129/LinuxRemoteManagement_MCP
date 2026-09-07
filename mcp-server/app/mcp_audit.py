"""MCP 監査ログ (JSONL)。

MCP Tool 呼び出しのすべてを構造化ログとして記録する。
設計書 §28 Level 2 "Audit Log" / Level 3 "Immutable audit log" に対応。

- 1行1エントリの JSON Lines、ファイルは 0600 (POSIX)
- 生トークンやファイル内容などの機密値は記録しない (パラメータは要約のみ)
- 破壊的操作には approval_id を含める
- 各エントリに SHA-256 のハッシュチェーンを付与し、改ざんを検知できる
  (Agent側 internal/audit/logger.go と同方式: prev_hash / hash フィールド)
"""

from __future__ import annotations

import hashlib
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


# ---- ハッシュチェーン (Immutable Audit Log) ----
#
# Agent側 (lrm-mcp-agent/internal/audit/logger.go) と同じ方式で、
# エントリの全フィールドを順序に依存せず連結した文字列を SHA-256 でハッシュ化する。
# 各エントリは prev_hash (1つ前のエントリのハッシュ) と hash を持ち、
# 1エントリでも改ざんすると以降のチェーンが破綻する。


def _ok_value(ok: bool | None) -> str:
    """ok フィールドを文字列へ正規化する (浮動/整数の表記揺れ対策込み)。"""
    if ok is True:
        return "true"
    if ok is False:
        return "false"
    return ""


def _duration_value(duration_ms: float | None) -> str:
    if duration_ms is None:
        return ""
    # round() 後の値は整数/小数どちらも JSON で同じ文字列へ往復する
    return str(round(duration_ms, 1))


def _entry_payload(entry: dict[str, Any], prev_hash: str) -> str:
    """ハッシュ入力を作る。JSON のキー順・空白に依存しないよう明示的に連結する。

    params は sort_keys=True で canonical 化するため、dict の挿入順が
    違ってもレコード内容が同じなら同じハッシュになる。
    """
    parts = [
        str(entry.get("timestamp", "")),
        str(entry.get("actor", "")),
        str(entry.get("action", "")),
        str(entry.get("server", "") or ""),
        json.dumps(entry.get("params") or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        _ok_value(entry.get("ok")),
        str(entry.get("error_kind", "") or ""),
        _duration_value(entry.get("duration_ms")),
        str(entry.get("detail", "") or ""),
        prev_hash,
    ]
    return "|".join(parts)


def _compute_hash(entry: dict[str, Any], prev_hash: str) -> str:
    """直前ハッシュとエントリ内容から SHA-256 (hex) を計算する。"""
    return hashlib.sha256(_entry_payload(entry, prev_hash).encode("utf-8")).hexdigest()


def read_last_hash(path: str | Path) -> str:
    """ログ末尾エントリのハッシュを復元する (再起動後もチェーンを継続するため)。"""
    p = Path(path)
    if not p.exists():
        return ""
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    for raw in reversed(lines):
        raw = raw.strip()
        if not raw:
            continue
        try:
            entry = json.loads(raw)
        except ValueError:
            continue
        hash_value = entry.get("hash")
        if hash_value:
            return hash_value
        # hash を持たない旧形式エントリが末尾にある場合は、そこからは
        # チェーンを継続できないため空 (新チェーン開始) として扱う。
        return ""
    return ""


def _read_log_text(path: Path) -> str | None:
    """ログファイルを読み、テキストを返す。`.gz` は展開する。失敗時は None。"""
    try:
        if path.name.endswith(".gz"):
            import gzip

            with gzip.open(path, "rb") as fh:
                data = fh.read()
            return data.decode("utf-8", errors="replace")
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def verify_audit_log(path: str | Path) -> list[str]:
    """監査ログ全体のハッシュチェーンを検証し、問題のリストを返す (正常なら空)。

    - 改ざんされた・チェーンが破綻したエントリはメッセージとして返す
    - hash フィールドを持たない旧形式エントリは検証対象外としてスキップする
    - 先頭エントリの prev_hash が空でない場合は、直前のログファイルへの
      参照とみなして許容する (ローテーション時の本来の挙動)
    - gzip 圧縮されたローテーション済みファイル (.1.gz 等) も検証できる
    """
    p = Path(path)
    if not p.exists():
        return [f"log file not found: {p}"]
    text = _read_log_text(p)
    if text is None:
        return [f"cannot read {p}"]
    lines = text.splitlines()
    problems: list[str] = []
    prev = ""
    for i, raw in enumerate(lines, 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            entry = json.loads(raw)
        except ValueError as exc:
            problems.append(f"line {i}: invalid JSON ({exc})")
            continue
        if not entry.get("hash"):
            continue  # 旧形式エントリは検証対象外
        if prev:
            if entry.get("prev_hash") != prev:
                problems.append(
                    f"line {i}: hash chain broken (prev_hash={entry.get('prev_hash')!r}, expected={prev!r})"
                )
            computed = _compute_hash(entry, prev)
        else:
            # 先頭: 前ファイルへの参照 (prev_hash) は検証できないため、
            # 自身の内容と参照先をもとにしたハッシュが正しいかだけ確認する
            computed = _compute_hash(entry, entry.get("prev_hash") or "")
        if computed != entry.get("hash"):
            problems.append(
                f"line {i}: tampering detected (stored={entry.get('hash')!r}, computed={computed!r})"
            )
        prev = entry.get("hash", "")
    return problems


class McpAudit:
    """JSONL 監査ログライタ（ローテーション対応）。"""

    def __init__(
        self,
        path: str | Path,
        enabled: bool = True,
        max_size_mb: int = 10,
        max_backups: int = 5,
        compress: bool = True,
        siem_webhook: str = "",
        siem_api_key: str = "",
    ):
        self.path = Path(path)
        self.enabled = enabled
        self.max_size_mb = max_size_mb
        self.max_backups = max_backups
        self.compress = compress
        self.siem_webhook = siem_webhook
        self.siem_api_key = siem_api_key
        self._lock = threading.Lock()
        self._fh = None
        self._last_hash = ""
        if self.enabled:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # 既存ログがあれば末尾ハッシュを復元してチェーンを継続する
            self._last_hash = read_last_hash(self.path)
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
        prev_hash = self._last_hash
        # Immutable Audit Log: ハッシュチェーンによる改ざん防止
        entry["prev_hash"] = prev_hash
        entry["hash"] = _compute_hash(entry, prev_hash)
        self._last_hash = entry["hash"]
        line = json.dumps(entry, ensure_ascii=False)
        try:
            with self._lock:
                self._fh.write(line + "\n")
                self._fh.flush()
        except OSError:
            pass
        if self.siem_webhook:
            self._siem_send(entry)

    def _siem_send(self, entry: dict[str, Any]) -> None:
        """ログエントリをSIEM webhookへ非同期で転送する (失敗してもログ本体に影響させない)。"""
        import httpx  # 遅延 import (テスト/短時間プロセスで不要)

        headers = {"Content-Type": "application/json"}
        if self.siem_api_key:
            headers["Authorization"] = f"Bearer {self.siem_api_key}"

        def _post() -> None:
            try:
                httpx.post(self.siem_webhook, json=entry, headers=headers, timeout=5.0)
            except Exception:  # noqa: BLE001
                pass

        threading.Thread(target=_post, daemon=True).start()

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

    @property
    def last_hash(self) -> str:
        """現在のハッシュチェーン末尾 (外部での保管・照合用)。"""
        return self._last_hash

    def verify(self) -> list[str]:
        """このファイルのハッシュチェーンを検証し、問題リストを返す (正常なら空)。"""
        if not self.path.exists():
            return [f"log file not found: {self.path}"]
        return verify_audit_log(self.path)

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            finally:
                self._fh = None
