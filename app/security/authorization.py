from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import Capability
from app.models.capabilities import UserCapability
from app.models.guild import Guild


class AuthorizationService:
    """Server-side capability gate for APXOR-controlled operations.

    Discord owner authority is checked against the current persisted guild owner
    identity. Non-owners must have an enabled, non-expired capability grant.
    This service never trusts a client-provided role name or UI state.
    """

    async def is_allowed(
        self,
        session: AsyncSession,
        *,
        guild_id: int,
        discord_user_id: int,
        capability: Capability,
    ) -> bool:
        guild = await session.scalar(
            select(Guild).where(Guild.discord_guild_id == guild_id)
        )
        if guild is None:
            return False

        if discord_user_id == guild.owner_discord_id:
            return True

        now = datetime.now(timezone.utc)
        grant = await session.scalar(
            select(UserCapability).where(
                UserCapability.guild_id == guild.id,
                UserCapability.discord_user_id == discord_user_id,
                UserCapability.capability == capability.value,
                UserCapability.enabled.is_(True),
            )
        )
        if grant is None:
            return False
        return grant.expires_at is None or grant.expires_at > now

    async def grant(
        self,
        session: AsyncSession,
        *,
        guild_id: int,
        discord_user_id: int,
        capability: Capability,
        granted_by_discord_id: int,
        expires_at: datetime | None = None,
    ) -> UserCapability:
        guild = await session.scalar(
            select(Guild).where(Guild.discord_guild_id == guild_id)
        )
        if guild is None:
            raise ValueError("Guild is not initialized in APXOR")
        if granted_by_discord_id != guild.owner_discord_id:
            allowed = await self.is_allowed(
                session,
                guild_id=guild_id,
                discord_user_id=granted_by_discord_id,
                capability=Capability.SECURITY_MANAGE,
            )
            if not allowed:
                raise PermissionError("SECURITY_MANAGE capability required")

        existing = await session.scalar(
            select(UserCapability).where(
                UserCapability.guild_id == guild.id,
                UserCapability.discord_user_id == discord_user_id,
                UserCapability.capability == capability.value,
            )
        )
        if existing is None:
            existing = UserCapability(
                guild_id=guild.id,
                discord_user_id=discord_user_id,
                capability=capability.value,
                granted_by_discord_id=granted_by_discord_id,
                expires_at=expires_at,
                enabled=True,
            )
            session.add(existing)
        else:
            existing.enabled = True
            existing.granted_by_discord_id = granted_by_discord_id
            existing.expires_at = expires_at
        await session.flush()
        return existing

    async def revoke(
        self,
        session: AsyncSession,
        *,
        guild_id: int,
        discord_user_id: int,
        capability: Capability,
        revoked_by_discord_id: int,
    ) -> bool:
        allowed = await self.is_allowed(
            session,
            guild_id=guild_id,
            discord_user_id=revoked_by_discord_id,
            capability=Capability.SECURITY_MANAGE,
        )
        if not allowed:
            raise PermissionError("SECURITY_MANAGE capability required")

        guild = await session.scalar(
            select(Guild).where(Guild.discord_guild_id == guild_id)
        )
        if guild is None:
            return False

        grant = await session.scalar(
            select(UserCapability).where(
                UserCapability.guild_id == guild.id,
                UserCapability.discord_user_id == discord_user_id,
                UserCapability.capability == capability.value,
            )
        )
        if grant is None:
            return False
        grant.enabled = False
        return True
