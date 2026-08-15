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
    """Return a safe dependency snapshot without treating advisory AI as a blocker.

    APEXOR's deterministic security path must continue to be considered ready when
    Groq is unavailable or dashboard authentication is not configured. AI is an
    advisory capability and the dashboard is a separate surface; neither is the
    root of trust for Discord security processing.
    """
    db_ok, db_status = await database_health()
    ai_configured = bool(settings.groq_api_key and settings.groq_model)
    dashboard_auth_configured = bool(settings.dashboard_session_secret)

    # Database connectivity is the API's core readiness dependency. AI and
    # dashboard auth are reported as degraded capabilities, not blockers for the
    # deterministic security core.
    core_ready = db_ok
    status = "ok" if core_ready and ai_configured and dashboard_auth_configured else "degraded"

    return {
        "status": status,
        "checks": {
            "database": db_status,
            "ai": "configured" if ai_configured else "not_configured",
            "dashboard_auth": "configured" if dashboard_auth_configured else "not_configured",
        },
        "ready": core_ready,
        "core_ready": core_ready,
    }
