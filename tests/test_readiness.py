from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.asyncio
async def test_liveness_endpoint() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["service"] == "apxor-api"


@pytest.mark.asyncio
async def test_readiness_endpoint_without_database() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/health/ready")

    # CI does not provide a production database. The endpoint must fail closed
    # rather than reporting the API as ready when persistence is unavailable.
    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"
    assert response.json()["database"] in {"not_configured", "unavailable"}
