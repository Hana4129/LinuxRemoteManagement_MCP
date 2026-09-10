"""設定ホットリロード機能のテスト。"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from app.config_reload import (
    ConfigManager,
    get_config,
    get_manager,
    reload_config,
    setup_config_reload,
)


@pytest.fixture
def config_file(tmp_path):
    """テスト用の設定ファイルを作成する。"""
    config_data = {
        "console": {
            "host": "127.0.0.1",
            "port": 8080,
            "data_dir": str(tmp_path / "data"),
            "mcp_http": True,
            "username": "",
            "password": "",
            "auth_required": False,
        },
        "agent": {
            "timeout_seconds": 5.0,
        },
        "servers": [
            {"id": "test-srv", "name": "Test Server", "url": "https://localhost:8443"},
        ],
    }
    config_path = tmp_path / "config.test.yml"
    with open(config_path, "w") as f:
        yaml.safe_dump(config_data, f)
    return config_path


class TestConfigManager:
    def test_initialize(self, config_file):
        from app.config import load_config
        config = load_config(config_file)
        mgr = ConfigManager()
        mgr.initialize(config)
        assert mgr.config is config

    def test_reload(self, config_file):
        from app.config import load_config
        config = load_config(config_file)
        mgr = ConfigManager()
        mgr.initialize(config)
        result = mgr.reload()
        assert result is True
        assert mgr.config is not None

    def test_on_reload_callback(self, config_file):
        from app.config import load_config
        config = load_config(config_file)
        mgr = ConfigManager()
        mgr.initialize(config)

        callback_called = []
        mgr.on_reload(lambda c: callback_called.append(c))

        mgr.reload()
        assert len(callback_called) == 1

    def test_config_property_when_uninitialized(self):
        mgr = ConfigManager()
        with pytest.raises(RuntimeError):
            _ = mgr.config

    def test_watcher_starts_and_stops(self, config_file):
        from app.config import load_config
        config = load_config(config_file)
        mgr = ConfigManager()
        mgr.initialize(config)
        # Watcher should be started
        assert mgr._watcher_thread is not None
        mgr.stop_watcher()
        assert mgr._watcher_thread is None


class TestModuleLevel:
    def test_setup_and_get(self, config_file, monkeypatch):
        monkeypatch.chdir(config_file.parent)
        from app.config import load_config
        config = load_config(config_file)
        setup_config_reload(config)
        current = get_config()
        assert current is config
