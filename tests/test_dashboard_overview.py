from fastapi.testclient import TestClient

from app.main import app


def test_dashboard_overview_requires_service_key(monkeypatch) -> None:
    monkeypatch.setattr("app.api.dashboard.settings.dashboard_api_key", "test-secret")

    response = TestClient(app).get("/api/dashboard/guilds/123/overview")

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid dashboard credentials."
