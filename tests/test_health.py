from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["service"] == "apexor-api"


def test_root() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["service"] == "APEXOR"


def test_deep_health_reports_degraded_dependencies(monkeypatch) -> None:
    async def fake_system_health() -> dict[str, object]:
        return {
            "status": "degraded",
            "checks": {
                "database": "unavailable",
                "ai": "not_configured",
                "dashboard_auth": "not_configured",
            },
            "ready": False,
        }

    monkeypatch.setattr("app.main.system_health", fake_system_health)
    response = client.get("/health/deep")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "degraded"
    assert body["ready"] is False
    assert body["checks"]["database"] == "unavailable"
    assert "GROQ_API_KEY" not in response.text
    assert "DASHBOARD_SESSION_SECRET" not in response.text
