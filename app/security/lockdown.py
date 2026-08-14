from __future__ import annotations

import logging

import discord
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import ProtectionState
from app.models.events import SecurityEventLog
from app.models.guild import Guild
from app.security.permissions.policy import DEFAULT_PERMISSION_POLICY

logger = logging.getLogger(__name__)


class LockdownEngine:
    """Deterministic containment layer for high-risk incidents."""

    def __init__(self) -> None:
        self.policy = DEFAULT_PERMISSION_POLICY

    async def enter_lockdown(
        self,
        session: AsyncSession,
        guild: discord.Guild,
        *,
        actor_id: int | None,
        event_log_id: int | None = None,
    ) -> str:
        db_guild = await session.scalar(select(Guild).where(Guild.discord_guild_id == guild.id))
        if db_guild is not None:
            db_guild.protection_state = ProtectionState.LOCKDOWN.value
            db_guild.protection_score = 100

        actions: list[str] = []
        bot_member = guild.me
        bot_top_role = bot_member.top_role if bot_member is not None else None

        if actor_id is not None and bot_top_role is not None:
            member = guild.get_member(actor_id)
            if member is not None and member.id != guild.owner_id:
                for role in member.roles:
                    if role.is_default() or role >= bot_top_role:
                        continue
                    current = role.permissions
                    critical = {
                        name
                        for name in self.policy.critical_permissions
                        if getattr(current, name, False)
                    }
                    if not critical:
                        continue

                    updated = discord.Permissions(current.value)
                    for name in critical:
                        setattr(updated, name, False)

                    try:
                        await role.edit(
                            permissions=updated,
                            reason="APXOR emergency lockdown: remove critical permissions",
                        )
                        actions.append(f"role:{role.id}:removed={','.join(sorted(critical))}")
                    except (discord.Forbidden, discord.HTTPException) as exc:
                        logger.warning(
                            "Could not contain role %s in guild %s: %s",
                            role.id,
                            guild.id,
                            exc,
                        )

        if event_log_id is not None:
            log = await session.scalar(select(SecurityEventLog).where(SecurityEventLog.id == event_log_id))
            if log is not None:
                log.status = "CONTAINED"
                log.action_taken = "; ".join(actions) if actions else "LOCKDOWN_STATE_ONLY"

        await session.commit()
        return "; ".join(actions) if actions else "LOCKDOWN_STATE_ONLY"
