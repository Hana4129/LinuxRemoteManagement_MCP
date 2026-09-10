"""MCP Server 設定ホットリロード機能。

SIGHUP シグナルまたは設定ファイル変更検知により、
再起動なしで設定を再読み込みする機能を提供する。

使用法:
    from app.config_reload import setup_config_reload, get_config, reload_config

    # 初期化時にセットアップ
    setup_config_reload(config)

    # 現在の設定を取得
    current_config = get_config()

    # 手動リロード
    reload_config()
"""

from __future__ import annotations

import logging
import os
import signal
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

from .config import AppConfig, load_config

logger = logging.getLogger(__name__)


class ConfigManager:
    """設定の読み込み・リロードを管理するスレッドセーフなマネージャー。"""

    def __init__(self) -> None:
        self._config: AppConfig | None = None
        self._lock = threading.RLock()
        self._watcher_thread: threading.Thread | None = None
        self._watcher_stop = threading.Event()
        self._on_reload: list[Callable[[AppConfig], None]] = []
        self._last_mtime: float = 0
        self._config_path: Path | None = None

    @property
    def config(self) -> AppConfig:
        """現在の設定を返す。初期化されていない場合はエラー。"""
        with self._lock:
            if self._config is None:
                raise RuntimeError("ConfigManager not initialized. Call initialize() first.")
            return self._config

    def initialize(self, config: AppConfig) -> None:
        """初期設定を登録し、ファイル監視を開始する。"""
        with self._lock:
            self._config = config
            self._config_path = getattr(config, "config_path", None)
            self._last_mtime = self._get_mtime()
        self._start_watcher()
        logger.info("ConfigManager initialized with config: %s", self._config_path)

    def _get_mtime(self) -> float:
        """設定ファイルの最終更新時刻を取得する。"""
        if self._config_path is None:
            return 0
        try:
            return os.path.getmtime(self._config_path)
        except OSError:
            return 0

    def reload(self) -> bool:
        """設定を再読み込みする。成功した場合は True。"""
        try:
            new_config = load_config()
            with self._lock:
                old_config = self._config
                self._config = new_config
                self._last_mtime = self._get_mtime()
            logger.info("Config reloaded successfully")
            for callback in self._on_reload:
                try:
                    callback(new_config)
                except Exception:
                    logger.exception("Config reload callback failed")
            return True
        except Exception:
            logger.exception("Config reload failed")
            return False

    def reload_from_path(self, path: Path) -> bool:
        """指定されたパスから設定を再読み込みする。"""
        try:
            from .config import _load_config_from_path
            new_config = _load_config_from_path(path)
            with self._lock:
                self._config = new_config
                self._config_path = path
                self._last_mtime = self._get_mtime()
            logger.info("Config reloaded from %s", path)
            for callback in self._on_reload:
                try:
                    callback(new_config)
                except Exception:
                    logger.exception("Config reload callback failed")
            return True
        except Exception:
            logger.exception("Config reload from %s failed", path)
            return False

    def on_reload(self, callback: Callable[[AppConfig], None]) -> None:
        """リロード完了時に呼び出すコールバックを登録する。"""
        self._on_reload.append(callback)

    def _start_watcher(self) -> None:
        """設定ファイルの変更監視スレッドを開始する。"""
        if self._watcher_thread is not None:
            return
        if self._config_path is None:
            return
        self._watcher_stop.clear()
        self._watcher_thread = threading.Thread(
            target=self._watcher_loop,
            daemon=True,
            name="config-watcher",
        )
        self._watcher_thread.start()
        logger.debug("Config watcher started for %s", self._config_path)

    def _watcher_loop(self) -> None:
        """設定ファイルの変更をポーリングで検知する。"""
        while not self._watcher_stop.wait(timeout=5):
            mtime = self._get_mtime()
            if mtime > self._last_mtime:
                logger.info("Config file changed, reloading...")
                self.reload()

    def stop_watcher(self) -> None:
        """ファイル監視を停止する。"""
        self._watcher_stop.set()
        if self._watcher_thread is not None:
            self._watcher_thread.join(timeout=10)
            self._watcher_thread = None

    def setup_sighup_handler(self) -> None:
        """SIGHUP シグナルハンドラを設定する。"""
        if os.name == "nt":
            logger.warning("SIGHUP not supported on Windows, skipping signal handler")
            return

        def handler(signum, frame):
            logger.info("Received SIGHUP, reloading config...")
            self.reload()

        try:
            signal.signal(signal.SIGHUP, handler)
            logger.debug("SIGHUP handler registered")
        except (OSError, ValueError) as exc:
            logger.warning("Failed to register SIGHUP handler: %s", exc)


# グローバルインスタンス
_config_manager = ConfigManager()


def get_manager() -> ConfigManager:
    """グローバルな ConfigManager インスタンスを返す。"""
    return _config_manager


def setup_config_reload(config: AppConfig) -> ConfigManager:
    """設定ホットリロードを初期化する。"""
    _config_manager.initialize(config)
    _config_manager.setup_sighup_handler()
    return _config_manager


def get_config() -> AppConfig:
    """現在の設定を返す。"""
    return _config_manager.config


def reload_config() -> bool:
    """設定を手動で再読み込みする。"""
    return _config_manager.reload()
