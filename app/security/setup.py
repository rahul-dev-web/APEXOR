from __future__ import annotations

import logging

import discord
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import ProtectionState
from app.models.guild import Guild
from app.models.security import SecurityChannel, SecurityConfig, SecurityRole
from app.models.snapshots import SecuritySnapshot
from app.security.snapshots import SnapshotService

logger = logging.getLogger(__name__)


class GuildAutoSetup:
    """Idempotent first-line protection bootstrap for a Discord guild."""

    CATEGORY_NAME = "APEXOR SECURITY"
    SECURITY_ROLE_NAME = "APEXOR-SECURITY"
    CHANNELS: tuple[tuple[str, str], ...] = (
        ("apexor-alerts", "ALERTS"),
        ("apexor-critical", "CRITICAL"),
        ("apexor-audit", "AUDIT"),
        ("apexor-recovery", "RECOVERY"),
    )

    def __init__(self) -> None:
        self.snapshots = SnapshotService()

    async def ensure(self, session: AsyncSession, guild: discord.Guild) -> bool:
        db_guild = await session.scalar(select(Guild).where(Guild.discord_guild_id == guild.id))
        if db_guild is None:
            db_guild = Guild(
                discord_guild_id=guild.id,
                name=guild.name,
                owner_discord_id=guild.owner_id,
                protection_state=ProtectionState.INITIALIZING.value,
                protection_score=0,
                is_active=True,
            )
            session.add(db_guild)

        config = await session.scalar(select(SecurityConfig).where(SecurityConfig.guild_id == guild.id))
        if config is None:
            config = SecurityConfig(guild_id=guild.id)
            session.add(config)
            await session.flush()

        security_role = await self._ensure_security_role(session, guild)
        category = self._find_category(guild)
        if category is None:
            category = await self._create_category(guild, security_role)
        await self._ensure_channels(session, guild, category, security_role)

        db_guild.protection_state = ProtectionState.PROTECTED.value
        db_guild.protection_score = 100
        db_guild.owner_discord_id = guild.owner_id
        db_guild.name = guild.name
        db_guild.is_active = True

        # Capture the baseline once. Reconnects must not generate unbounded
        # duplicate snapshots; later event-driven snapshots create new versions.
        if config.snapshot_enabled:
            existing = await session.scalar(
                select(func.count(SecuritySnapshot.id)).where(SecuritySnapshot.guild_id == guild.id)
            )
            if not existing:
                await self.snapshots.capture_guild(session, guild, source="AUTO_SETUP")

        await session.commit()
        logger.info("APEXOR auto-setup complete: guild=%s", guild.id)
        return True

    async def _ensure_security_role(self, session: AsyncSession, guild: discord.Guild) -> discord.Role:
        role = discord.utils.get(guild.roles, name=self.SECURITY_ROLE_NAME)
        if role is None:
            role = await guild.create_role(
                name=self.SECURITY_ROLE_NAME,
                permissions=discord.Permissions.none(),
                reason="APEXOR security bootstrap",
            )

        row = await session.scalar(
            select(SecurityRole).where(
                SecurityRole.guild_id == guild.id,
                SecurityRole.discord_role_id == role.id,
            )
        )
        if row is None:
            session.add(
                SecurityRole(
                    guild_id=guild.id,
                    discord_role_id=role.id,
                    role_type="SECURITY",
                    role_name=role.name,
                    is_protected=True,
                )
            )
        return role

    def _find_category(self, guild: discord.Guild) -> discord.CategoryChannel | None:
        return discord.utils.get(guild.categories, name=self.CATEGORY_NAME)

    async def _create_category(self, guild: discord.Guild, security_role: discord.Role) -> discord.CategoryChannel:
        overwrites: dict[discord.abc.Snowflake, discord.PermissionOverwrite] = {
            guild.default_role: discord.PermissionOverwrite(view_channel=False),
            security_role: discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True),
        }
        if guild.owner is not None:
            overwrites[guild.owner] = discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True)
        return await guild.create_category(self.CATEGORY_NAME, overwrites=overwrites, reason="APEXOR security bootstrap")

    async def _ensure_channels(
        self, session: AsyncSession, guild: discord.Guild, category: discord.CategoryChannel, security_role: discord.Role
    ) -> None:
        for channel_name, channel_type in self.CHANNELS:
            channel = discord.utils.get(category.channels, name=channel_name)
            if channel is None:
                channel = await guild.create_text_channel(channel_name, category=category, reason="APEXOR security bootstrap")

            row = await session.scalar(
                select(SecurityChannel).where(
                    SecurityChannel.guild_id == guild.id,
                    SecurityChannel.discord_channel_id == channel.id,
                )
            )
            if row is None:
                session.add(
                    SecurityChannel(
                        guild_id=guild.id,
                        discord_channel_id=channel.id,
                        channel_type=channel_type,
                        channel_name=channel.name,
                        is_protected=True,
                    )
                )
