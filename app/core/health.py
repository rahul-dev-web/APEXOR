from __future__ import annotations

from sqlalchemy import text

from app.core.config import settings
from app.database.session import SessionLocal


async def database_health() -> tuple[bool, str]:
    """Check database connectivity without mutating application state."""
    if SessionLocal is None:
        return False, "not_configured"

    try:
        async with SessionLocal() as session:
            await session.execute(text("SELECT 1"))
        return True, "ok"
    except Exception:
        return False, "unavailable"


async def system_health() -> dict[str, object]:
    """Return a safe, non-secret dependency health snapshot for operations."""
    db_ok, db_status = await database_health()
    ai_configured = bool(settings.groq_api_key and settings.groq_model)
    dashboard_auth_configured = bool(settings.dashboard_session_secret)

    checks = {
        "database": db_ok,
        "ai": ai_configured,
        "dashboard_auth": dashboard_auth_configured,
    }
    overall_ok = all(checks.values())

    return {
        "status": "ok" if overall_ok else "degraded",
        "checks": {
            "database": db_status,
            "ai": "configured" if ai_configured else "not_configured",
            "dashboard_auth": "configured" if dashboard_auth_configured else "not_configured",
        },
        "ready": overall_ok,
    }
