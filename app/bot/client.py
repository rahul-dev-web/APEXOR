import logging

import discord

from app.core.config import settings
from app.security.permissions.audit import PermissionAudit

logger = logging.getLogger(__name__)


class APXORClient(discord.Client):
    """Discord Gateway client for APXOR's security core.

    The initial Gateway surface intentionally requests only the guilds intent.
    Member intent is not required for the current permission/event pipeline and
    should not be enabled until a feature explicitly needs it.
    """

    def __init__(self) -> None:
        intents = discord.Intents.none()
        intents.guilds = True

        super().__init__(intents=intents)
        self.permission_audit = PermissionAudit()

    async def setup_hook(self) -> None:
        logger.info("APXOR Discord client setup initialized")

    async def on_ready(self) -> None:
        logger.info(
            "APXOR connected as %s (%s)",
            self.user,
            self.user.id if self.user else "unknown",
        )
        logger.info("Connected guilds: %d", len(self.guilds))

        for guild in self.guilds:
            self._log_permission_findings(guild)

    async def on_guild_join(self, guild: discord.Guild) -> None:
        logger.info("APXOR joined guild %s (%s)", guild.name, guild.id)
        self._log_permission_findings(guild)

    async def on_guild_role_create(self, role: discord.Role) -> None:
        self._log_permission_findings(role.guild)

    async def on_guild_role_update(self, before: discord.Role, after: discord.Role) -> None:
        if before.permissions.value != after.permissions.value:
            logger.warning(
                "Role permission change detected: guild=%s role=%s before=%s after=%s",
                after.guild.id,
                after.id,
                before.permissions.value,
                after.permissions.value,
            )
        self._log_permission_findings(after.guild)

    async def on_guild_role_delete(self, role: discord.Role) -> None:
        logger.warning(
            "Guild role deleted: guild=%s role=%s name=%s",
            role.guild.id,
            role.id,
            role.name,
        )

    def _log_permission_findings(self, guild: discord.Guild) -> None:
        for finding in self.permission_audit.audit_guild(guild):
            logger.warning(
                "Privileged role detected: guild=%s role=%s name=%r severity=%s permissions=%s owner_role=%s",
                guild.id,
                finding.role_id,
                finding.role_name,
                finding.severity,
                ",".join(finding.permissions),
                finding.is_owner_role,
            )

    async def start_bot(self) -> None:
        if not settings.discord_token:
            raise RuntimeError("DISCORD_TOKEN is not configured")
        await self.start(settings.discord_token)
