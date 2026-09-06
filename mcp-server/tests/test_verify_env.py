"""verify_env.py (実環境検証プリフライト) の動作テスト。"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_env.py"

_MINIMAL_CONFIG = """
console:
  host: 127.0.0.1
  port: 8080
  data_dir: ./data
  username: admin
  password: secret
agent:
  timeout_seconds: 2
  tls_verify: true
servers: []
"""


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(cwd),
        timeout=180,
    )


def test_verify_env_offline_json_ok(tmp_path: Path) -> None:
    config = tmp_path / "config.yml"
    config.write_text(_MINIMAL_CONFIG, encoding="utf-8")

    proc = _run(["--config", str(config), "--json"], cwd=tmp_path)

    out = proc.stdout
    assert proc.returncode == 0, f"stderr={proc.stderr}\nstdout={out}"
    data = json.loads(out)
    assert data["summary"]["FAIL"] == 0
    tasks = {c["task"] for c in data["checks"]}
    # 主要タスクの索引が含まれること
    assert {"P0-2/P2-12", "P2-10", "P2-9", "P0-1/P2-11", "P1-5", "P1-6", "P1-4"} <= tasks
    # 設定読み込みは PASS
    config_check = next(c for c in data["checks"] if c["title"] == "config.yml 読み込み")
    assert config_check["status"] == "PASS"


def test_verify_env_bad_config_fails(tmp_path: Path) -> None:
    missing = tmp_path / "no-such-config.yml"

    proc = _run(["--config", str(missing), "--json"], cwd=tmp_path)

    data = json.loads(proc.stdout)
    assert proc.returncode == 1
    assert data["summary"]["FAIL"] >= 1


def test_verify_env_text_output(tmp_path: Path) -> None:
    config = tmp_path / "config.yml"
    config.write_text(_MINIMAL_CONFIG, encoding="utf-8")

    proc = _run(["--config", str(config)], cwd=tmp_path)

    assert proc.returncode == 0
    assert "summary: PASS=" in proc.stdout
    assert "doc/EnvVerification.md" in proc.stdout
