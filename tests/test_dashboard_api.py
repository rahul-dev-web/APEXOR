import pytest
from fastapi import HTTPException

from app.api.dashboard import require_dashboard_key
from app.core.config import settings


@pytest.mark.asyncio
async def test_dashboard_key_is_required(monkeypatch):
    monkeypatch.setattr(settings, "dashboard_api_key", "test-secret")

    with pytest.raises(HTTPException) as exc:
        await require_dashboard_key(None)

    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_dashboard_key_accepts_valid_secret(monkeypatch):
    monkeypatch.setattr(settings, "dashboard_api_key", "test-secret")

    result = await require_dashboard_key("test-secret")
    assert result is None
