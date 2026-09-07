"""OIDC JWT validation for management-console authentication."""

from __future__ import annotations

import time
from threading import RLock
from typing import Any

import httpx
import jwt


class OidcError(Exception):
    """Raised when an OIDC token cannot be validated."""


class OidcValidator:
    def __init__(self, issuer: str, audience: str, jwks_url: str, cache_seconds: int = 300):
        if not issuer or not audience or not jwks_url:
            raise ValueError("OIDCには issuer, audience, jwks_url が必要です")
        if not jwks_url.startswith("https://"):
            raise ValueError("oidc_jwks_url は https:// である必要があります")

        self.issuer = issuer
        self.audience = audience
        self.jwks_url = jwks_url
        self.cache_seconds = cache_seconds
        self._keys: dict[str, Any] = {}
        self._loaded_at = 0.0
        self._lock = RLock()

    def _load_keys(self) -> dict[str, Any]:
        with self._lock:
            if self._keys and time.monotonic() - self._loaded_at < self.cache_seconds:
                return self._keys
            response = httpx.get(self.jwks_url, timeout=5.0)
            response.raise_for_status()
            jwks = jwt.PyJWKSet.from_dict(response.json())
            self._keys = {key.key_id: key.key for key in jwks.keys if key.key_id}
            self._loaded_at = time.monotonic()
            return self._keys

    def validate(self, raw_token: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(raw_token)
            kid = header.get("kid")
            if not kid:
                raise OidcError("OIDC tokenにkidがありません")
            key = self._load_keys().get(kid)
            if key is None:
                self._loaded_at = 0.0
                key = self._load_keys().get(kid)
            if key is None:
                raise OidcError("OIDC tokenの署名鍵が見つかりません")
            return jwt.decode(
                raw_token,
                key=key,
                algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
                issuer=self.issuer,
                audience=self.audience,
                options={"require": ["sub", "iss", "aud", "exp"]},
            )
        except (jwt.PyJWTError, httpx.HTTPError, ValueError, OidcError) as exc:
            if isinstance(exc, OidcError):
                raise
            raise OidcError("OIDC tokenの検証に失敗しました") from exc