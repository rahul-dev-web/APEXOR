from __future__ import annotations

import asyncio
import logging
import sys

from app.bot.client import APEXORClient
from app.core.config import settings

logger = logging.getLogger(__name__)


async def run() -> None:
    if not settings.discord_token:
        raise RuntimeError("DISCORD_TOKEN is not configured")

    client = APEXORClient()
    try:
        await client.start(settings.discord_token)
    finally:
        if not client.is_closed():
            await client.close()


if __name__ == "__main__":
    logging.basicConfig(level=settings.log_level)
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(run())
