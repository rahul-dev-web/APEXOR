from scripts.production_preflight import validate_environment


def _set_valid_environment(monkeypatch) -> None:
    values = {
        "APP_ENV": "production",
        "DISCORD_TOKEN": "test-token",
        "DATABASE_URL": "postgresql://user:password@example.com/apxor",
        "DISCORD_CLIENT_ID": "123",
        "DISCORD_CLIENT_SECRET": "secret",
        "DISCORD_REDIRECT_URI": "https://api.example.com/api/dashboard/auth/callback",
        "DASHBOARD_FRONTEND_URL": "https://dashboard.example.com",
        "DASHBOARD_SESSION_SECRET": "x" * 64,
        "GROQ_API_KEY": "",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_production_preflight_accepts_valid_configuration(monkeypatch) -> None:
    _set_valid_environment(monkeypatch)

    results = validate_environment()

    assert all(result.ok for result in results)


def test_production_preflight_rejects_localhost_production_urls(monkeypatch) -> None:
    _set_valid_environment(monkeypatch)
    monkeypatch.setenv("DISCORD_REDIRECT_URI", "http://localhost:8000/callback")
    monkeypatch.setenv("DASHBOARD_FRONTEND_URL", "http://localhost:3000")

    results = validate_environment()
    failures = {result.name for result in results if not result.ok}

    assert "DISCORD_REDIRECT_URI" in failures
    assert "DASHBOARD_FRONTEND_URL" in failures


def test_production_preflight_keeps_groq_optional(monkeypatch) -> None:
    _set_valid_environment(monkeypatch)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    results = validate_environment()
    groq_result = next(result for result in results if result.name == "GROQ_API_KEY")

    assert groq_result.ok is True
    assert "degraded" in groq_result.detail


def test_production_preflight_requires_strong_session_secret(monkeypatch) -> None:
    _set_valid_environment(monkeypatch)
    monkeypatch.setenv("DASHBOARD_SESSION_SECRET", "too-short")

    results = validate_environment()
    failures = {result.name for result in results if not result.ok}

    assert "DASHBOARD_SESSION_SECRET length" in failures
