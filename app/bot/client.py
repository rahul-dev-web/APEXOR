import logging

import discord

from app.core.config import settings

logger = logging.getLogger(__name__)


class APXORClient(discord.Client):
    def __init__(self) -> None:
        intents = discord.Intents.none()
        intents.guilds = True
        intents.members = True

        super().__init__(intents=intents)

    async def setup_hook(self) -> None:
        logger.info("APXOR Discord client setup initialized")

    async def on_ready(self) -> None:
        logger.info("APXOR connected as %s (%s)", self.user, self.user.id if self.user else "unknown")
        logger.info("Connected guilds: %d", len(self.guilds))

    async def start_bot(self) -> None:
        if not settings.discord_token:
            raise RuntimeError("DISCORD_TOKEN is not configured")
        await self.start(settings.discord_token)
