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


_STATE_RANK = {
    ProtectionState.INITIALIZING: 0,
    ProtectionState.PROTECTED: 1,
    ProtectionState.DEGRADED: 2,
    ProtectionState.SUSPICIOUS: 3,
    ProtectionState.HIGH_RISK: 4,
    ProtectionState.LOCKDOWN: 5,
    ProtectionState.RECOVERING: 6,
    ProtectionState.RECOVERY_FAILED: 7,
    ProtectionState.DISABLED: -1,
}


def state_for_risk(score: int) -> ProtectionState:
    """Map a deterministic risk score to the guild protection state."""
    if score >= 95:
        return ProtectionState.LOCKDOWN
    if score >= 80:
        return ProtectionState.HIGH_RISK
    if score >= 60:
        return ProtectionState.SUSPICIOUS
    return ProtectionState.PROTECTED


def should_enter_lockdown(score: int, *, threshold: int = 80) -> bool:
    """Return whether a risk score crosses the configured containment boundary."""
    return score >= threshold


class LockdownEngine:
    """Deterministic containment layer for high-risk incidents."""

    def __init__(self) -> None:
        self.policy = DEFAULT_PERMISSION_POLICY

    async def set_protection_state(
        self,
        session: AsyncSession,
        guild_id: int,
        state: ProtectionState,
        *,
        score: int,
    ) -> bool:
        """Persist a state transition without allowing a lower-risk event to downgrade containment."""
        db_guild = await session.scalar(select(Guild).where(Guild.discord_guild_id == guild_id))
        if db_guild is None:
            return False

        current = ProtectionState(db_guild.protection_state)
        # DISABLED is an explicit administrative state and must never be
        # overridden by an automatic event.
        if current == ProtectionState.DISABLED:
            return False

        if _STATE_RANK.get(state, 0) < _STATE_RANK.get(current, 0):
            return False

        db_guild.protection_state = state.value
        db_guild.protection_score = max(0, min(score, 100))
        await session.flush()
        return True

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
            await self.set_protection_state(
                session,
                guild.id,
                ProtectionState.LOCKDOWN,
                score=100,
            )

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
