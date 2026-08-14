import logging

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app.api.dashboard import router as dashboard_router
from app.core.config import settings
from app.core.health import database_health
from app.core.logging import configure_logging

configure_logging(settings.log_level)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="APXOR API",
    version="0.2.0",
    description="Security-first Discord anti-nuke platform API.",
)

app.include_router(dashboard_router)


@app.get("/health")
async def health() -> dict[str, str]:
    """Liveness endpoint: process is running and able to serve HTTP."""
    return {
        "status": "ok",
        "service": "apxor-api",
        "environment": settings.app_env,
    }


@app.get("/health/ready")
async def readiness() -> JSONResponse:
    """Readiness endpoint suitable for deployment health checks.

    Unlike /health, this verifies that the configured PostgreSQL connection is
    usable. The endpoint never exposes connection strings or database errors.
    """
    db_ok, db_status = await database_health()
    status_code = 200 if db_ok else 503
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "ready" if db_ok else "not_ready",
            "service": "apxor-api",
            "database": db_status,
        },
    )


@app.get("/")
async def root() -> dict[str, str]:
    return {"service": "APXOR", "status": "online"}
