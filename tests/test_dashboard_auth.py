from __future__ import annotations

import pytest

from app.security.dashboard_auth import DashboardSessionSigner


def test_dashboard_session_round_trip() -> None:
    signer = DashboardSessionSigner("x" * 40, ttl_seconds=60)
    token = signer.issue(user_id=123, guild_ids={3, 1}, now=1000)
    principal = signer.verify(token, now=1059)
    assert principal.user_id == 123
    assert principal.guild_ids == frozenset({1, 3})
    assert principal.expires_at == 1060


def test_dashboard_session_rejects_tampering() -> None:
    signer = DashboardSessionSigner("x" * 40, ttl_seconds=60)
    token = signer.issue(user_id=123, guild_ids={1}, now=1000)
    encoded, signature = token.split(".", 1)
    tampered = f"{encoded[:-1]}A.{signature}"
    with pytest.raises(ValueError, match="invalid dashboard session"):
        signer.verify(tampered, now=1001)


def test_dashboard_session_rejects_expiry() -> None:
    signer = DashboardSessionSigner("x" * 40, ttl_seconds=60)
    token = signer.issue(user_id=123, guild_ids={1}, now=1000)
    with pytest.raises(ValueError, match="invalid dashboard session"):
        signer.verify(token, now=1060)


def test_dashboard_session_requires_strong_secret() -> None:
    with pytest.raises(ValueError, match="at least 32"):
        DashboardSessionSigner("short")


def test_dashboard_csrf_token_is_bound_to_session() -> None:
    signer = DashboardSessionSigner("x" * 40, ttl_seconds=60)
    session_a = signer.issue(user_id=123, guild_ids={1}, now=1000)
    session_b = signer.issue(user_id=123, guild_ids={1}, now=1000)
    csrf = signer.issue_csrf_token(session_a)

    assert signer.verify_csrf_token(session_a, csrf)
    assert not signer.verify_csrf_token(session_b, csrf)


def test_dashboard_csrf_token_rejects_tampering() -> None:
    signer = DashboardSessionSigner("x" * 40, ttl_seconds=60)
    session = signer.issue(user_id=123, guild_ids={1}, now=1000)
    csrf = signer.issue_csrf_token(session)
    nonce, signature = csrf.split(".", 1)
    tampered = f"{nonce}X.{signature}"

    assert not signer.verify_csrf_token(session, tampered)
