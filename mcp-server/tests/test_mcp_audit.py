"""McpAudit (mcp_audit.py) の単体テスト。"""
from __future__ import annotations

import json
from pathlib import Path

from app.mcp_audit import (
    McpAudit,
    _compute_hash,
    read_last_hash,
    sanitize_params,
    verify_audit_log,
)


def test_sanitize_params_masks_sensitive_keys():
    out = sanitize_params({"token": "lra_secret", "Authorization": "Bearer x", "path": "/etc/os-release"})
    assert out["token"] == "***"
    assert out["Authorization"] == "***"
    assert out["path"] == "/etc/os-release"


def test_sanitize_params_truncates_long_values():
    long = "a" * 500
    out = sanitize_params({"value": long})
    assert len(out["value"]) == 200 + 1  # 切り詰め + 省略記号
    assert out["value"].startswith("a" * 200)


def test_sanitize_params_empty_and_none():
    assert sanitize_params(None) == {}
    assert sanitize_params({}) == {}


def test_log_writes_jsonl_entries(audit: McpAudit):
    audit.log(actor="mcp:ci", action="get_system_info", server="dev-web-01", params={}, ok=True, duration_ms=12.34)
    audit.log(actor="mcp:ci", action="restart_service", server="dev-web-01",
              params={"service": "nginx", "token": "lra_x"}, ok=False, error_kind="approval_required")
    entries = audit.read_entries()
    assert len(entries) == 2
    first = entries[0]
    assert first["actor"] == "mcp:ci"
    assert first["action"] == "get_system_info"
    assert first["server"] == "dev-web-01"
    assert first["ok"] is True
    assert first["duration_ms"] == 12.3
    second = entries[1]
    assert second["ok"] is False
    assert second["error_kind"] == "approval_required"
    assert second["params"]["token"] == "***"  # 機密キーはマスクされる


def test_log_file_is_jsonl_format(tmp_dir, audit: McpAudit):
    audit.log(actor="mcp", action="list_servers", ok=True)
    lines = audit.path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["action"] == "list_servers"


def test_disabled_audit_writes_nothing(tmp_dir):
    a = McpAudit(tmp_dir / "off.jsonl", enabled=False)
    a.log(actor="mcp", action="get_system_info", ok=True)
    assert not a.path.exists()
    a.close()


def test_close_is_idempotent(audit: McpAudit):
    audit.log(actor="mcp", action="x", ok=True)
    audit.close()
    audit.close()  # 2回呼んでもエラーにならない


def test_siem_webhook_receives_entry(tmp_path, monkeypatch):
    """siem_webhook が設定されている場合、各ログエントリが webhook へ POST される。"""
    posted: list = []

    def fake_post(url, json=None, headers=None, timeout=None):
        posted.append({"url": url, "json": json, "headers": headers})

        class _Resp:
            status_code = 200

        return _Resp()

    monkeypatch.setattr("httpx.post", fake_post)
    audit = McpAudit(tmp_path / "audit.jsonl", siem_webhook="https://siem.example/ingest")
    audit.log(actor="mcp:ci", action="get_system_info", server="dev-web-01", ok=True, duration_ms=12.3)
    audit.close()
    # 非同期スレッドの完了を待つ
    import time
    time.sleep(0.2)
    assert len(posted) == 1
    assert posted[0]["url"] == "https://siem.example/ingest"
    assert posted[0]["json"]["action"] == "get_system_info"
    assert posted[0]["json"]["server"] == "dev-web-01"


def test_siem_webhook_uses_api_key(tmp_path, monkeypatch):
    """siem_api_key が設定されている場合、Authorization ヘッダーが付与される。"""
    posted: list = []

    def fake_post(url, json=None, headers=None, timeout=None):
        posted.append(headers)

        class _Resp:
            status_code = 200

        return _Resp()

    monkeypatch.setattr("httpx.post", fake_post)
    audit = McpAudit(tmp_path / "audit.jsonl", siem_webhook="https://siem.example/ingest", siem_api_key="secret-key")
    audit.log(actor="mcp", action="x", ok=True)
    audit.close()
    import time
    time.sleep(0.2)
    assert posted[0]["Authorization"] == "Bearer secret-key"


def test_siem_webhook_failure_does_not_break_logging(tmp_path, monkeypatch):
    """webhook 送信が失敗してもログファイルへの書き込みは成功する。"""
    def fake_post(url, json=None, headers=None, timeout=None):
        raise RuntimeError("network error")

    monkeypatch.setattr("httpx.post", fake_post)
    audit = McpAudit(tmp_path / "audit.jsonl", siem_webhook="https://siem.example/ingest")
    audit.log(actor="mcp", action="get_system_info", ok=True)
    entries = audit.read_entries()
    assert len(entries) == 1
    assert entries[0]["action"] == "get_system_info"
    audit.close()


def test_no_siem_webhook_no_post(tmp_path, monkeypatch):
    """siem_webhook が空の場合、httpx.post は呼ばれない。"""
    called = []

    def fake_post(url, json=None, headers=None, timeout=None):
        called.append(True)

        class _Resp:
            status_code = 200

        return _Resp()

    monkeypatch.setattr("httpx.post", fake_post)
    audit = McpAudit(tmp_path / "audit.jsonl")
    audit.log(actor="mcp", action="x", ok=True)
    audit.close()
    import time
    time.sleep(0.1)
    assert called == []


# ---- ハッシュチェーン (Immutable Audit Log) ----


def test_entries_have_hash_chain_fields(tmp_dir, audit: McpAudit):
    audit.log(actor="mcp:ci", action="get_system_info", server="dev-web-01", ok=True)
    audit.log(actor="mcp:ci", action="restart_service", server="dev-web-01", ok=False)
    entries = audit.read_entries()
    assert len(entries) == 2
    first, second = entries
    assert first["prev_hash"] == ""
    assert first["hash"]
    assert second["prev_hash"] == first["hash"], "2番目のエントリは1つ前のハッシュを参照する"
    assert first["hash"] == _compute_hash(first, "")


def test_verify_ok_on_clean_log(tmp_dir, audit: McpAudit):
    audit.log(actor="mcp", action="a", ok=True)
    audit.log(actor="mcp", action="b", server="dev-web-01", ok=False)
    audit.close()
    assert verify_audit_log(tmp_dir / "mcp_audit.jsonl") == []


def test_verify_detects_tampered_field(tmp_path):
    audit = McpAudit(tmp_path / "audit.jsonl")
    audit.log(actor="mcp", action="get_system_info", server="dev-web-01", ok=True)
    audit.log(actor="mcp", action="restart_service", server="dev-web-01", ok=False)
    audit.close()
    path = tmp_path / "audit.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    # 1行目の actor を書き換える (2行目以降の prev_hash が破綻する)
    tampered_line = lines[0].replace('"actor": "mcp"', '"actor": "attacker"')
    path.write_text("\n".join([tampered_line] + lines[1:]) + "\n", encoding="utf-8")
    problems = verify_audit_log(path)
    assert problems, "改ざんが検知されること"
    assert any("tampering" in p or "chain broken" in p for p in problems)


def test_verify_detects_chain_break(tmp_path):
    audit = McpAudit(tmp_path / "audit.jsonl")
    audit.log(actor="mcp", action="a", ok=True)
    audit.log(actor="mcp", action="b", ok=True)
    audit.log(actor="mcp", action="c", ok=True)
    audit.close()
    path = tmp_path / "audit.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    third = json.loads(lines[2])
    third["prev_hash"] = "0" * 64  # チェーンを破壊
    lines[2] = json.dumps(third, ensure_ascii=False)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    problems = verify_audit_log(path)
    assert any("chain broken" in p for p in problems)


def test_read_last_hash_restores_chain(tmp_path):
    """再起動 (新インスタンス) でも前の末尾ハッシュからチェーンを継続する。"""
    audit = McpAudit(tmp_path / "audit.jsonl")
    audit.log(actor="mcp", action="a", ok=True)
    audit.close()
    last = audit.last_hash
    assert verify_audit_log(tmp_path / "audit.jsonl") == []

    audit2 = McpAudit(tmp_path / "audit.jsonl")
    audit2.log(actor="mcp", action="b", ok=True)
    audit2.close()
    assert read_last_hash(tmp_path / "audit.jsonl") == audit2.last_hash
    entries = audit2.read_entries()
    assert entries[0]["hash"] == last
    assert entries[1]["prev_hash"] == last, "再起動後もチェーンが継続する"
    assert verify_audit_log(tmp_path / "audit.jsonl") == []


def test_verify_skips_legacy_entries(tmp_path):
    """hash を持たない旧形式エントリは検証対象外としてスキップし、後続チェーンは検証する。"""
    path = tmp_path / "audit.jsonl"
    path.write_text(
        json.dumps({"timestamp": "2026-01-01T00:00:00Z", "actor": "mcp", "action": "legacy", "ok": True}) + "\n",
        encoding="utf-8",
    )
    audit = McpAudit(path)
    audit.log(actor="mcp", action="new-style", ok=True)
    audit.close()
    assert verify_audit_log(path) == []


def test_verify_missing_file(tmp_path):
    problems = verify_audit_log(tmp_path / "nope.jsonl")
    assert problems and "not found" in problems[0]


def test_verify_command_cli(tmp_path):
    """python -m app.verify_audit_log が正常で終了コード 0 を返す。"""
    audit = McpAudit(tmp_path / "audit.jsonl")
    audit.log(actor="mcp", action="a", ok=True)
    audit.close()
    import os
    import subprocess
    import sys
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
    ok = subprocess.run(
        [sys.executable, "-m", "app.verify_audit_log", str(tmp_path / "audit.jsonl")],
        capture_output=True, text=True, env=env,
    )
    assert ok.returncode == 0, ok.stdout + ok.stderr
    # 改ざんしたログは終了コード 1
    path = tmp_path / "audit.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace('"action": "a"', '"action": "evil"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    bad = subprocess.run(
        [sys.executable, "-m", "app.verify_audit_log", str(path)],
        capture_output=True, text=True, env=env,
    )
    assert bad.returncode == 1, bad.stdout + bad.stderr


def test_verify_gzip_rotated_file(tmp_path):
    """gzip 圧縮されたローテーション済みログ (.1.gz) も検証できる。"""
    import gzip
    audit = McpAudit(tmp_path / "audit.log")
    audit.log(actor="mcp", action="a", ok=True)
    audit.log(actor="mcp", action="b", ok=True)
    audit.close()
    path = tmp_path / "audit.log"
    gz = tmp_path / "audit.log.1.gz"
    with open(path, "rb") as f_in, gzip.open(gz, "wb") as f_out:
        while chunk := f_in.read(65536):
            f_out.write(chunk)
    assert verify_audit_log(gz) == []
    # 解凍せずそのまま読める (テキストファイルも動く)
    assert verify_audit_log(path) == []
