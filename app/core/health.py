from __future__ import annotations

from sqlalchemy import text

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
