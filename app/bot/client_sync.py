from __future__ import annotations

import discord

from app.bot.client import APEXORClient


class SyncedAPEXORClient(APEXORClient):
    """APEXOR client that makes the existing global command tree available immediately.

    The security client keeps the canonical command handlers. This adapter only
    copies the global command definitions into each guild before the existing
    guild-scoped sync, avoiding Discord's global-command propagation delay.
    """

    async def on_ready(self) -> None:
        for guild in self.guilds:
            self.tree.copy_global_to(guild=guild)
        await super().on_ready()

    async def on_guild_join(self, guild: discord.Guild) -> None:
        self.tree.copy_global_to(guild=guild)
        await super().on_guild_join(guild)
