"""Secret Store abstraction layer for token storage.

Provides a pluggable interface for storing tokens in different backends:
- LocalEncryptedFile: AES-256-GCM encrypted file (default, current behavior)
- HashiCorpVault: Vault KV v2 integration (optional)

The interface mirrors the minimal operations needed by TokenStore.
"""
from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from .secretbox import SecretBox, resolve_secret_box

logger = logging.getLogger("linux_mcp.secret_store")


class SecretStoreError(Exception):
    """Base exception for Secret Store operations."""


class SecretStore(ABC):
    """Abstract interface for token secret storage backends."""

    @abstractmethod
    def store(self, key: str, value: str) -> None:
        """Store a secret value under the given key."""

    @abstractmethod
    def retrieve(self, key: str) -> str | None:
        """Retrieve a secret value by key. Returns None if not found."""

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete a secret by key. Returns True if deleted."""

    @abstractmethod
    def list_keys(self, prefix: str = "") -> list[str]:
        """List all keys, optionally filtered by prefix."""


class LocalEncryptedFileStore(SecretStore):
    """Stores secrets as AES-256-GCM encrypted JSON file.

    This is the default backend. The encryption key is managed via
    the SecretBox (environment variable or key file).
    """

    def __init__(self, store_path: str | Path, *, box: SecretBox | None = None) -> None:
        self._path = Path(store_path)
        self._box = box or resolve_secret_box(key_file=self._path.parent / "secret_store.key")
        self._data: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                import json
                raw = self._path.read_text(encoding="utf-8")
                self._data = json.loads(raw)
            except Exception as exc:
                logger.warning("Failed to load secret store: %s", exc)
                self._data = {}

    def _save(self) -> None:
        import json
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        try:
            os.chmod(self._path, 0o600)
        except OSError:
            pass

    def store(self, key: str, value: str) -> None:
        self._data[key] = self._box.encrypt(value)
        self._save()

    def retrieve(self, key: str) -> str | None:
        encrypted = self._data.get(key)
        if encrypted is None:
            return None
        try:
            return self._box.decrypt(encrypted)
        except Exception as exc:
            logger.error("Failed to decrypt secret %s: %s", key, exc)
            raise SecretStoreError(f"decryption failed for {key}") from exc

    def delete(self, key: str) -> bool:
        if key in self._data:
            del self._data[key]
            self._save()
            return True
        return False

    def list_keys(self, prefix: str = "") -> list[str]:
        return [k for k in self._data if k.startswith(prefix)]


class HashiCorpVaultStore(SecretStore):
    """HashiCorp Vault KV v2 backend.

    Requires: pip install hvac
    Environment: VAULT_ADDR, VAULT_TOKEN (or VAULT_ROLE_ID/VAULT_SECRET_ID for AppRole)
    """

    def __init__(self, mount: str = "secret", path: str = "linux-mcp") -> None:
        try:
            import hvac
        except ImportError as exc:
            raise SecretStoreError(
                "hvac package required for Vault integration: pip install hvac"
            ) from exc
        self._mount = mount
        self._path = path
        url = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
        token = os.environ.get("VAULT_TOKEN")
        self._client = hvac.Client(url=url, token=token)
        if not self._client.is_authenticated():
            self._try_approle_auth()

    def _try_approle_auth(self) -> None:
        import hvac
        role_id = os.environ.get("VAULT_ROLE_ID")
        secret_id = os.environ.get("VAULT_SECRET_ID")
        if role_id and secret_id:
            self._client.auth.approle.login(role_id=role_id, secret_id=secret_id)

    def _kv_path(self, key: str) -> str:
        return f"{self._path}/{key}"

    def store(self, key: str, value: str) -> None:
        self._client.secrets.kv.v2.create_or_update_secret(
            path=self._kv_path(key), secret={"value": value}, mount_point=self._mount
        )

    def retrieve(self, key: str) -> str | None:
        try:
            resp = self._client.secrets.kv.v2.read_secret_version(
                path=self._kv_path(key), mount_point=self._mount
            )
            return resp["data"]["data"].get("value")
        except Exception:
            return None

    def delete(self, key: str) -> bool:
        try:
            self._client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=self._kv_path(key), mount_point=self._mount
            )
            return True
        except Exception:
            return False

    def list_keys(self, prefix: str = "") -> list[str]:
        try:
            resp = self._client.secrets.kv.v2.list_secrets(
                path=self._path, mount_point=self._mount
            )
            keys = resp.get("data", {}).get("keys", [])
            return [k for k in keys if k.startswith(prefix)]
        except Exception:
            return []


def create_secret_store(backend: str | None = None, **kwargs: Any) -> SecretStore:
    """Factory function to create a SecretStore based on configuration.

    Args:
        backend: "local" (default), "vault", or None (auto-detect from env)
        **kwargs: Passed to the backend constructor
    """
    if backend is None:
        backend = "vault" if os.environ.get("VAULT_ADDR") else "local"
    if backend == "vault":
        return HashiCorpVaultStore(**kwargs)
    return LocalEncryptedFileStore(**kwargs)
