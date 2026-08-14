from __future__ import annotations

import logging

import discord
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import ProtectionState
from app.models.events import SecurityEventLog
from app.models.guild import Guild
from app.security.permissions.policy import DEFAULT_PERMISSION_POLICY
from app.security.persistence import SecurityPersistence

logger = logging.getLogger(__name__)


# State transitions are deliberately explicit.  A security incident must never
# be able to jump from containment directly back to PROTECTED merely because a
# later low-risk event was observed.
_ALLOWED_TRANSITIONS: dict[ProtectionState, frozenset[ProtectionState]] = {
    ProtectionState.INITIALIZING: frozenset(
        {ProtectionState.PROTECTED, ProtectionState.DEGRADED, ProtectionState.DISABLED}
    ),
    ProtectionState.PROTECTED: frozenset(
        {
            ProtectionState.DEGRADED,
            ProtectionState.SUSPICIOUS,
            ProtectionState.HIGH_RISK,
            ProtectionState.LOCKDOWN,
            ProtectionState.DISABLED,
        }
    ),
    ProtectionState.DEGRADED: frozenset(
        {
            ProtectionState.PROTECTED,
            ProtectionState.SUSPICIOUS,
            ProtectionState.HIGH_RISK,
            ProtectionState.LOCKDOWN,
            ProtectionState.DISABLED,
        }
    ),
    ProtectionState.SUSPICIOUS: frozenset(
        {
            ProtectionState.PROTECTED,
            ProtectionState.DEGRADED,
            ProtectionState.HIGH_RISK,
            ProtectionState.LOCKDOWN,
            ProtectionState.DISABLED,
        }
    ),
    ProtectionState.HIGH_RISK: frozenset(
        {
            ProtectionState.LOCKDOWN,
            ProtectionState.RECOVERING,
            ProtectionState.DEGRADED,
            ProtectionState.DISABLED,
        }
    ),
    ProtectionState.LOCKDOWN: frozenset(
        {
            ProtectionState.RECOVERING,
            ProtectionState.RECOVERY_FAILED,
            ProtectionState.DISABLED,
        }
    ),
    ProtectionState.RECOVERING: frozenset(
        {
            ProtectionState.PROTECTED,
            ProtectionState.DEGRADED,
            ProtectionState.LOCKDOWN,
            ProtectionState.RECOVERY_FAILED,
            ProtectionState.DISABLED,
        }
    ),
    ProtectionState.RECOVERY_FAILED: frozenset(
        {
            ProtectionState.RECOVERING,
            ProtectionState.LOCKDOWN,
            ProtectionState.DEGRADED,
            ProtectionState.DISABLED,
        }
    ),
    ProtectionState.DISABLED: frozenset(
        {ProtectionState.INITIALIZING, ProtectionState.PROTECTED}
    ),
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


def can_transition(
    current: ProtectionState, target: ProtectionState
) -> bool:
    """Return whether a protection-state transition is explicitly permitted."""
    if current == target:
        return True
    return target in _ALLOWED_TRANSITIONS.get(current, frozenset())


class LockdownEngine:
    """Deterministic containment and recovery state machine."""

    def __init__(self) -> None:
        self.policy = DEFAULT_PERMISSION_POLICY
        self.persistence = SecurityPersistence()

    async def set_protection_state(
        self,
        session: AsyncSession,
        guild_id: int,
        state: ProtectionState,
        *,
        score: int,
        force: bool = False,
    ) -> bool:
        """Persist a valid state transition.

        ``force`` is reserved for trusted lifecycle operations such as explicit
        administrator recovery/reset. Normal event processing must use the
        state machine so that a benign event cannot downgrade an active
        lockdown.
        """
        db_guild = await session.scalar(select(Guild).where(Guild.discord_guild_id == guild_id))
        if db_guild is None:
            return False

        current = ProtectionState(db_guild.protection_state)
        if current == state:
            db_guild.protection_score = max(0, min(score, 100))
            await session.flush()
            return True

        if not force and not can_transition(current, state):
            logger.warning(
                "Rejected invalid protection transition guild=%s %s -> %s",
                guild_id,
                current,
                state,
            )
            return False

        db_guild.protection_state = state.value
        db_guild.protection_score = max(0, min(score, 100))
        await session.flush()
        return True

    async def begin_recovery(
        self, session: AsyncSession, guild_id: int, *, score: int = 100
    ) -> bool:
        """Move a contained/high-risk guild into the recovery state."""
        return await self.set_protection_state(
            session,
            guild_id,
            ProtectionState.RECOVERING,
            score=score,
        )

    async def mark_recovery_failed(
        self, session: AsyncSession, guild_id: int, *, score: int = 100
    ) -> bool:
        """Record that recovery could not safely complete."""
        return await self.set_protection_state(
            session,
            guild_id,
            ProtectionState.RECOVERY_FAILED,
            score=score,
        )

    async def complete_recovery(
        self, session: AsyncSession, guild_id: int, *, score: int = 0
    ) -> bool:
        """Return a successfully reconstructed guild to normal protection."""
        return await self.set_protection_state(
            session,
            guild_id,
            ProtectionState.PROTECTED,
            score=score,
        )

    async def enter_lockdown(
        self,
        session: AsyncSession,
        guild: discord.Guild,
        *,
        actor_id: int | None,
        event_log_id: int | None = None,
    ) -> str:
        if db_guild := await session.scalar(select(Guild).where(Guild.discord_guild_id == guild.id)):
            await self.set_protection_state(
                session,
                guild.id,
                ProtectionState.LOCKDOWN,
                score=100,
            )

        if event_log_id is not None:
            await self.persistence.mark_containment_started(session, event_log_id)

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

        containment_success = bool(actions) or actor_id is None or bot_top_role is None
        if event_log_id is not None:
            log = await session.scalar(select(SecurityEventLog).where(SecurityEventLog.id == event_log_id))
            if log is not None:
                log.status = "CONTAINED" if containment_success else "CONTAINMENT_FAILED"
                log.action_taken = "; ".join(actions) if actions else "LOCKDOWN_STATE_ONLY"
            await self.persistence.mark_contained(session, event_log_id, success=containment_success)

        await session.commit()
        return "; ".join(actions) if actions else "LOCKDOWN_STATE_ONLY"
