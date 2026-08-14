import logging

from fastapi import FastAPI

from app.core.config import settings
from app.core.logging import configure_logging

configure_logging(settings.log_level)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="APXOR API",
    version="0.1.0",
    description="Security-first Discord anti-nuke platform API.",
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "apxor-api",
        "environment": settings.app_env,
    }


@app.get("/")
async def root() -> dict[str, str]:
    return {"service": "APXOR", "status": "online"}
