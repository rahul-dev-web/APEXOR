from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.events import SecurityEventLog, SecurityIncident
from app.models.guild import Guild
from app.security.events import Detection


_HIGH = 60
_CRITICAL = 80
_EMERGENCY = 95


def severity_for(score: int) -> str:
    if score >= _EMERGENCY:
        return "EMERGENCY"
    if score >= _CRITICAL:
        return "CRITICAL"
    if score >= _HIGH:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"


class SecurityPersistence:
    """Persist normalized detections without making DB availability a security dependency."""

    async def ensure_guild(self, session: AsyncSession, guild_id: int, *, name: str, owner_id: int) -> None:
        guild = await session.scalar(select(Guild).where(Guild.discord_guild_id == guild_id))
        if guild is None:
            session.add(
                Guild(
                    discord_guild_id=guild_id,
                    name=name[:100],
                    owner_discord_id=owner_id,
                    protection_state="PROTECTED",
                )
            )
            await session.flush()
        else:
            guild.name = name[:100]
            guild.owner_discord_id = owner_id

    async def record(self, session: AsyncSession, detection: Detection) -> int | None:
        event = detection.event
        existing = await session.scalar(
            select(SecurityEventLog).where(
                SecurityEventLog.guild_id == event.guild_id,
                SecurityEventLog.fingerprint == event.fingerprint,
            )
        )
        if existing is not None:
            return None

        severity = severity_for(detection.signal.score)
        log = SecurityEventLog(
            guild_id=event.guild_id,
            fingerprint=event.fingerprint,
            event_type=event.event_type.value,
            severity=severity,
            actor_discord_id=event.actor_id,
            target_discord_id=event.target_id,
            audit_log_id=event.audit_log_id,
            risk_score=detection.signal.score,
            velocity_count=detection.velocity_count,
            velocity_window_seconds=int(detection.velocity_window_seconds),
            reason=detection.signal.reason,
            status="OBSERVED",
        )
        session.add(log)
        await session.flush()

        if detection.signal.score >= _HIGH:
            session.add(
                SecurityIncident(
                    incident_key=f"{event.guild_id}:{event.fingerprint}",
                    guild_id=event.guild_id,
                    actor_discord_id=event.actor_id,
                    incident_type=event.event_type.value,
                    severity=severity,
                    risk_score=detection.signal.score,
                    status="OPEN",
                    event_count=1,
                    summary=detection.signal.reason,
                )
            )

        await session.commit()
        return log.id
