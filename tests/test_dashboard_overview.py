from types import SimpleNamespace

import pytest

from app.api.overview import overview


class _FakeSession:
    def __init__(self) -> None:
        self.calls = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def scalar(self, statement):
        self.calls += 1
        values = [
            SimpleNamespace(
                id=7,
                discord_guild_id=123,
                name="Test Guild",
                owner_discord_id=456,
                is_active=True,
                last_seen_at=None,
                protection_state="PROTECTED",
                protection_score=100,
            ),
            SimpleNamespace(
                anti_nuke_enabled=True,
                permission_enforcement_enabled=True,
                lockdown_enabled=True,
                recovery_enabled=True,
            ),
            2,
            1,
            0,
            3,
            4,
        ]
        return values[self.calls - 1]


@pytest.mark.asyncio
async def test_dashboard_overview_aggregates_persisted_security_state(monkeypatch) -> None:
    fake_session = _FakeSession()
    monkeypatch.setattr("app.api.overview.SessionLocal", lambda: fake_session)

    result = await overview(123)

    assert result["guild"]["id"] == 123
    assert result["guild"]["owner_id"] == 456
    assert result["protection"] == {
        "state": "PROTECTED",
        "score": 100,
        "anti_nuke_enabled": True,
        "permission_enforcement_enabled": True,
        "lockdown_enabled": True,
        "recovery_enabled": True,
    }
    assert result["security_metrics"] == {
        "critical_or_higher_events": 2,
        "open_incidents": 1,
        "active_recovery_actions": 0,
        "snapshots": 3,
        "ai_assessments": 4,
    }
