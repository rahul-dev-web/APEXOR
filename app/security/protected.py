from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.security import SecurityChannel, SecurityRole


class ProtectedResourceService:
    """Database-backed protected-resource lookup.

    Protected resources are an input to deterministic risk scoring; this service
    does not perform Discord mutations.
    """

    async def is_protected_target(
        self,
        session: AsyncSession,
        *,
        guild_id: int,
        target_id: int | None,
        event_type: str,
    ) -> bool:
        if target_id is None:
            return False

        if event_type.startswith("CHANNEL_"):
            row = await session.scalar(
                select(SecurityChannel.id).where(
                    SecurityChannel.guild_id == guild_id,
                    SecurityChannel.discord_channel_id == target_id,
                    SecurityChannel.is_protected.is_(True),
                )
            )
            return row is not None

        if event_type.startswith("ROLE_"):
            row = await session.scalar(
                select(SecurityRole.id).where(
                    SecurityRole.guild_id == guild_id,
                    SecurityRole.discord_role_id == target_id,
                    SecurityRole.is_protected.is_(True),
                )
            )
            return row is not None

        return False
