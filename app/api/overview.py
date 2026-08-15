from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select

from app.api.dashboard_auth import require_dashboard_guild_access
from app.database.session import SessionLocal
from app.models.ai import AIThreatAssessment
from app.models.events import SecurityEventLog, SecurityIncident
from app.models.guild import Guild
from app.models.recovery import RecoveryAction
from app.models.security import SecurityConfig
from app.models.snapshots import SecuritySnapshot

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/guilds/{guild_id}/overview", dependencies=[Depends(require_dashboard_guild_access)])
async def overview(guild_id: int) -> dict:
    """Return one compact dashboard payload for the server security center.

    Access is protected by the same Discord OAuth guild authorization used by
    the other guild-scoped dashboard endpoints. The endpoint only reads
    persisted state; it never invokes Discord REST calls, mutates security
    state, or invokes Groq.
    """
    if SessionLocal is None:
        raise HTTPException(status_code=503, detail="Database is unavailable.")

    async with SessionLocal() as session:
        guild = await session.scalar(select(Guild).where(Guild.discord_guild_id == guild_id))
        if guild is None:
            raise HTTPException(status_code=404, detail="Guild is not registered with APXOR.")

        config = await session.scalar(select(SecurityConfig).where(SecurityConfig.guild_id == guild.id))
        critical_events = await session.scalar(
            select(func.count(SecurityEventLog.id)).where(
                SecurityEventLog.guild_id == guild.id,
                SecurityEventLog.severity.in_(("HIGH", "CRITICAL", "EMERGENCY")),
            )
        )
        open_incidents = await session.scalar(
            select(func.count(SecurityIncident.id)).where(
                SecurityIncident.guild_id == guild.id,
                SecurityIncident.status.not_in(("RESOLVED", "CLOSED")),
            )
        )
        active_recovery = await session.scalar(
            select(func.count(RecoveryAction.id)).where(
                RecoveryAction.guild_id == guild.id,
                RecoveryAction.status.in_(("PENDING", "RUNNING", "RETRY")),
            )
        )
        snapshot_count = await session.scalar(
            select(func.count(SecuritySnapshot.id)).where(SecuritySnapshot.guild_id == guild.id)
        )
        ai_count = await session.scalar(
            select(func.count(AIThreatAssessment.id)).where(AIThreatAssessment.guild_id == guild.id)
        )

        return {
            "guild": {
                "id": guild.discord_guild_id,
                "name": guild.name,
                "owner_id": guild.owner_discord_id,
                "active": guild.is_active,
                "last_seen_at": guild.last_seen_at,
            },
            "protection": {
                "state": guild.protection_state,
                "score": guild.protection_score,
                "anti_nuke_enabled": bool(config and config.anti_nuke_enabled),
                "permission_enforcement_enabled": bool(config and config.permission_enforcement_enabled),
                "lockdown_enabled": bool(config and config.lockdown_enabled),
                "recovery_enabled": bool(config and config.recovery_enabled),
            },
            "security_metrics": {
                "critical_or_higher_events": int(critical_events or 0),
                "open_incidents": int(open_incidents or 0),
                "active_recovery_actions": int(active_recovery or 0),
                "snapshots": int(snapshot_count or 0),
                "ai_assessments": int(ai_count or 0),
            },
        }
