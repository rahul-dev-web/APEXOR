import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.dashboard import router as dashboard_router
from app.api.dashboard_auth import router as dashboard_auth_router
from app.api.overview import router as overview_router
from app.core.config import settings
from app.core.health import database_health, system_health
from app.core.logging import configure_logging

configure_logging(settings.log_level)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="APXOR API",
    version="0.3.2",
    description="Security-first Discord anti-nuke platform API.",
)

# The dashboard uses an HttpOnly session cookie. When the frontend is deployed
# separately (for example Vercel -> Render), browser credentials are cross-origin
# and must be explicitly allowed. Never use a wildcard origin with credentials.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.dashboard_frontend_url.rstrip("/")],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Accept", "Content-Type", "X-APXOR-Dashboard-Key"],
)

app.include_router(dashboard_router)
app.include_router(dashboard_auth_router)
app.include_router(overview_router)


@app.get("/health")
async def health() -> dict[str, str]:
    """Liveness endpoint: process is running and able to serve HTTP."""
    return {"status": "ok", "service": "apxor-api", "environment": settings.app_env}


@app.get("/health/ready")
async def readiness() -> JSONResponse:
    """Readiness endpoint suitable for deployment health checks."""
    db_ok, db_status = await database_health()
    status_code = 200 if db_ok else 503
    return JSONResponse(
        status_code=status_code,
        content={"status": "ready" if db_ok else "not_ready", "service": "apxor-api", "database": db_status},
    )


@app.get("/health/deep")
async def deep_health() -> JSONResponse:
    """Safe operational dependency snapshot; never returns secret values."""
    snapshot = await system_health()
    return JSONResponse(status_code=200 if snapshot["ready"] else 503, content=snapshot)


@app.get("/")
async def root() -> dict[str, str]:
    return {"service": "APXOR", "status": "online"}
