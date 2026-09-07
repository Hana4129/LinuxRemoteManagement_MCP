"""config.py (env var expansion / save with secret preservation) の動作テスト。"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from app.config import (
    _ENV_REF_PATTERN,
    _expand_env,
    _preserve_env_ref,
    _resolve_env_ref,
    load_config,
)


# ---------------------------------------------------------------------------
# _resolve_env_ref / _expand_env
# ---------------------------------------------------------------------------


def test_resolve_env_ref_simple(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_TEST_VAR", "hello")
    result = _ENV_REF_PATTERN.sub(_resolve_env_ref, "${MY_TEST_VAR}")
    assert result == "hello"


def test_resolve_env_ref_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MISSING_TEST_VAR", raising=False)
    assert _ENV_REF_PATTERN.sub(_resolve_env_ref, "${MISSING_TEST_VAR:-fallback}") == "fallback"
    assert _ENV_REF_PATTERN.sub(_resolve_env_ref, "${MISSING_TEST_VAR:-}") == ""


def test_resolve_env_ref_unset_no_default_raises() -> None:
    """fail-closed: 未設定の環境変数はValueError。"""
    with pytest.raises(ValueError, match="未設定"):
        _ENV_REF_PATTERN.sub(_resolve_env_ref, "${DEFINITELY_UNSET_VAR_12345}")


def test_expand_env_string(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_SECRET", "s3cret")
    assert _expand_env("password: ${MY_SECRET}") == "password: s3cret"


def test_expand_env_nested_dict(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DB_PASS", "dbpass123")
    raw = {"console": {"password": "${DB_PASS}"}, "agent": {"admin_token": "${DB_PASS}"}}
    expanded = _expand_env(raw)
    assert expanded["console"]["password"] == "dbpass123"
    assert expanded["agent"]["admin_token"] == "dbpass123"


def test_expand_env_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TOKEN_A", "tok_a")
    monkeypatch.setenv("TOKEN_B", "tok_b")
    raw = ["${TOKEN_A}", "${TOKEN_B}", "plain"]
    assert _expand_env(raw) == ["tok_a", "tok_b", "plain"]


def test_expand_env_non_string_passthrough() -> None:
    assert _expand_env(42) == 42
    assert _expand_env(True) is True
    assert _expand_env(None) is None


# ---------------------------------------------------------------------------
# _preserve_env_ref
# ---------------------------------------------------------------------------


def test_preserve_env_ref_when_set() -> None:
    """raw に ${ENV_VAR} があれば、resolved 値ではなく参照を返す。"""
    source = {"password": "${MCP_PASSWORD}", "plain": "hello"}
    assert _preserve_env_ref(source, "password", "resolved_secret") == "${MCP_PASSWORD}"


def test_preserve_env_ref_when_plaintext() -> None:
    """raw がプレーンテキストの場合は resolved 値を返す。"""
    source = {"password": "plaintext_secret"}
    assert _preserve_env_ref(source, "password", "plaintext_secret") == "plaintext_secret"


def test_preserve_env_ref_when_missing_key() -> None:
    source = {}
    assert _preserve_env_ref(source, "password", "resolved") == "resolved"


def test_preserve_env_ref_when_source_none() -> None:
    assert _preserve_env_ref(None, "password", "resolved") == "resolved"


# ---------------------------------------------------------------------------
# load_config + save round-trip with env var preservation
# ---------------------------------------------------------------------------

_ENV_REF_CONFIG = """\
console:
  host: 127.0.0.1
  port: 8080
  data_dir: {data_dir}
  auth_required: false
  auth_mode: basic
  password: ${{TEST_CONFIG_PASSWORD}}
  siem_api_key: ${{TEST_CONFIG_SIEM_KEY:-}}
agent:
  admin_token: ${{TEST_CONFIG_AGENT_TOKEN}}
  timeout_seconds: 5
  tls_verify: false
servers:
  - id: dev-web-01
    name: test
    url: http://127.0.0.1:8443
    env: development
"""


@pytest.fixture(autouse=True)
def _set_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_CONFIG_PASSWORD", "supersecret123")
    monkeypatch.setenv("TEST_CONFIG_AGENT_TOKEN", "agent-token-xyz")
    monkeypatch.delenv("TEST_CONFIG_SIEM_KEY", raising=False)


def test_load_config_resolves_env_refs(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yml"
    config_path.write_text(_ENV_REF_CONFIG.format(data_dir=str(tmp_path)), encoding="utf-8")
    config = load_config(str(config_path))
    assert config.console.password == "supersecret123"
    assert config.agent.admin_token == "agent-token-xyz"
    assert config.console.siem_api_key == ""


def test_save_preserves_env_refs(tmp_path: Path) -> None:
    """save() 後、config.yml に ${ENV_VAR} 参照が平文で書き出されないこと。"""
    config_path = tmp_path / "config.yml"
    config_path.write_text(_ENV_REF_CONFIG.format(data_dir=str(tmp_path)), encoding="utf-8")
    config = load_config(str(config_path))
    config.save()

    saved = config_path.read_text(encoding="utf-8")
    # 平文のシークレットが書き込まれていないことを確認
    assert "supersecret123" not in saved, "password が平文で config.yml に書き出されています!"
    assert "agent-token-xyz" not in saved, "admin_token が平文で config.yml に書き出されています!"
    # env var 参照が保持されていること
    assert "${TEST_CONFIG_PASSWORD}" in saved
    assert "${TEST_CONFIG_AGENT_TOKEN}" in saved


def test_save_preserves_env_ref_with_default(tmp_path: Path) -> None:
    """${ENV_VAR:-} (空デフォルト) も save() 時に参照を保持すること。"""
    config_path = tmp_path / "config.yml"
    config_path.write_text(_ENV_REF_CONFIG.format(data_dir=str(tmp_path)), encoding="utf-8")
    config = load_config(str(config_path))
    config.save()

    saved = config_path.read_text(encoding="utf-8")
    assert "${TEST_CONFIG_SIEM_KEY:-}" in saved, "siem_api_key の env ref が失われました"


def test_save_plaintext_when_no_env_ref(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """raw に ${ENV_VAR} がなければ、plaintext の password はそのまま保存される。"""
    monkeypatch.delenv("TEST_CONFIG_PASSWORD", raising=False)
    monkeypatch.delenv("TEST_CONFIG_AGENT_TOKEN", raising=False)
    monkeypatch.delenv("TEST_CONFIG_SIEM_KEY", raising=False)

    config_path = tmp_path / "config.yml"
    plaintext_config = _ENV_REF_CONFIG.format(data_dir=str(tmp_path)).replace(
        "password: ${TEST_CONFIG_PASSWORD}", "password: mypassword123"
    ).replace(
        "admin_token: ${TEST_CONFIG_AGENT_TOKEN}", "admin_token: mytoken456"
    ).replace(
        "siem_api_key: ${TEST_CONFIG_SIEM_KEY:-}", ""
    )
    config_path.write_text(plaintext_config, encoding="utf-8")

    config = load_config(str(config_path))
    config.save()

    saved = config_path.read_text(encoding="utf-8")
    assert "mypassword123" in saved
    assert "mytoken456" in saved


def test_load_config_unset_env_ref_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """env var 参照先が未設定かつデフォルトもない場合は fail-closed でエラー。"""
    monkeypatch.delenv("TEST_CONFIG_PASSWORD", raising=False)
    monkeypatch.setenv("TEST_CONFIG_AGENT_TOKEN", "t")
    monkeypatch.delenv("TEST_CONFIG_SIEM_KEY", raising=False)

    config_path = tmp_path / "config.yml"
    config_path.write_text(_ENV_REF_CONFIG.format(data_dir=str(tmp_path)), encoding="utf-8")

    with pytest.raises(ValueError, match="未設定"):
        load_config(str(config_path))
