"""Start the Discord worker only after the database schema is migrated.

Render starts web services and workers independently. The web service owns the
Alembic migration step, so the worker waits for the migration head before it
starts touching security tables. This prevents a cold deploy race where the
Gateway worker boots against an incomplete schema.
"""

from __future__ import annotations

import asyncio
import logging

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text

from app.bot.runner import run
from app.database.session import engine

logger = logging.getLogger(__name__)

WAIT_SECONDS = 3
TIMEOUT_SECONDS = 300


def migration_heads() -> set[str]:
    config = Config("alembic.ini")
    return set(ScriptDirectory.from_config(config).get_heads())


async def wait_for_migrations() -> None:
    if engine is None:
        raise RuntimeError("DATABASE_URL is not configured")

    heads = migration_heads()
    if not heads:
        raise RuntimeError("No Alembic migration head is configured")

    deadline = asyncio.get_running_loop().time() + TIMEOUT_SECONDS
    last_error: Exception | None = None

    while asyncio.get_running_loop().time() < deadline:
        try:
            async with engine.connect() as connection:
                result = await connection.execute(text("SELECT version_num FROM alembic_version"))
                versions = {str(row[0]) for row in result.fetchall()}
                if versions & heads:
                    logger.info("Database migration head verified: %s", sorted(versions))
                    return
                last_error = RuntimeError(
                    f"database migration is not at the current head; found={sorted(versions)} expected={sorted(heads)}"
                )
        except Exception as exc:  # database may not exist until web migration starts
            last_error = exc

        logger.info("Waiting for database migrations to reach head: %s", last_error)
        await asyncio.sleep(WAIT_SECONDS)

    raise TimeoutError(f"Timed out waiting for Alembic migrations: {last_error}")


async def main() -> None:
    await wait_for_migrations()
    await run()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
