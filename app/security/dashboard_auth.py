from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class DashboardPrincipal:
    user_id: int
    guild_ids: frozenset[int]
    expires_at: int


class DashboardSessionSigner:
    """Small stateless, tamper-evident dashboard session format.

    The session contains only Discord identity/access metadata and an expiry.
    It is HMAC signed; no Discord access token or client secret is placed in
    the browser cookie.
    """

    def __init__(self, secret: str, ttl_seconds: int = 3600) -> None:
        if len(secret) < 32:
            raise ValueError("DASHBOARD_SESSION_SECRET must be at least 32 characters")
        self._secret = secret.encode("utf-8")
        self.ttl_seconds = ttl_seconds

    @staticmethod
    def _encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    @staticmethod
    def _decode(value: str) -> bytes:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    def _sign(self, payload: str) -> str:
        digest = hmac.new(self._secret, payload.encode("ascii"), hashlib.sha256).digest()
        return self._encode(digest)

    def issue(self, *, user_id: int, guild_ids: set[int], now: int | None = None) -> str:
        issued_at = int(time.time()) if now is None else now
        payload = {
            "uid": user_id,
            "gids": sorted(guild_ids),
            "iat": issued_at,
            "exp": issued_at + self.ttl_seconds,
            "nonce": secrets.token_urlsafe(12),
        }
        encoded = self._encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        return f"{encoded}.{self._sign(encoded)}"

    def verify(self, token: str, *, now: int | None = None) -> DashboardPrincipal:
        try:
            encoded, signature = token.split(".", 1)
            expected = self._sign(encoded)
            if not hmac.compare_digest(signature, expected):
                raise ValueError("invalid signature")
            payload = json.loads(self._decode(encoded))
            current = int(time.time()) if now is None else now
            if int(payload["exp"]) <= current:
                raise ValueError("expired session")
            user_id = int(payload["uid"])
            guild_ids = frozenset(int(gid) for gid in payload["gids"])
            return DashboardPrincipal(user_id=user_id, guild_ids=guild_ids, expires_at=int(payload["exp"]))
        except (ValueError, KeyError, TypeError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("invalid dashboard session") from exc
