from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.events import SecurityEventLog, SecurityIncident
from app.models.guild import Guild
from app.models.security import SecurityConfig
from app.security.events import Detection


_HIGH = 60
_CRITICAL = 80
_EMERGENCY = 95
_INCIDENT_WINDOW_SECONDS = 30


def severity_for(score: int, *, high: int = _HIGH, critical: int = _CRITICAL, emergency: int = _EMERGENCY) -> str:
    if score >= emergency:
        return "EMERGENCY"
    if score >= critical:
        return "CRITICAL"
    if score >= high:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"


def incident_family(event_type: str) -> str:
    """Collapse related event types into an incident-level attack family."""
    if event_type.startswith("CHANNEL_"):
        return "CHANNEL_NUKE"
    if event_type.startswith("ROLE_"):
        return "ROLE_NUKE"
    if event_type in {"GUILD_UPDATE", "WEBHOOKS_UPDATE", "INTEGRATION_CREATE", "INTEGRATION_UPDATE", "INTEGRATION_DELETE"}:
        return "GUILD_TAMPERING"
    if event_type in {"MEMBER_REMOVE", "MEMBER_UPDATE", "BAN_ADD", "BAN_REMOVE", "KICK"}:
        return "MEMBER_MODERATION"
    return "SECURITY_ACTIVITY"


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

    async def record(
        self,
        session: AsyncSession,
        detection: Detection,
        *,
        high_threshold: int | None = None,
        critical_threshold: int | None = None,
        emergency_threshold: int | None = None,
    ) -> int | None:
        event = detection.event
        existing = await session.scalar(
            select(SecurityEventLog).where(
                SecurityEventLog.guild_id == event.guild_id,
                SecurityEventLog.fingerprint == event.fingerprint,
            )
        )
        if existing is not None:
            return None

        config = await session.scalar(select(SecurityConfig).where(SecurityConfig.guild_id == event.guild_id))
        high_threshold = high_threshold if high_threshold is not None else (config.risk_threshold_high if config else _HIGH)
        critical_threshold = critical_threshold if critical_threshold is not None else (config.risk_threshold_critical if config else _CRITICAL)
        emergency_threshold = emergency_threshold if emergency_threshold is not None else (config.risk_threshold_emergency if config else _EMERGENCY)

        severity = severity_for(
            detection.signal.score,
            high=high_threshold,
            critical=critical_threshold,
            emergency=emergency_threshold,
        )
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

        if detection.signal.score >= high_threshold:
            await self._upsert_incident(session, detection, severity=severity)

        await session.commit()
        return log.id

    async def _upsert_incident(
        self,
        session: AsyncSession,
        detection: Detection,
        *,
        severity: str,
    ) -> None:
        event = detection.event
        family = incident_family(event.event_type.value)
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=_INCIDENT_WINDOW_SECONDS)

        query = select(SecurityIncident).where(
            SecurityIncident.guild_id == event.guild_id,
            SecurityIncident.incident_type == family,
            SecurityIncident.status == "OPEN",
            SecurityIncident.created_at >= cutoff,
        )
        if event.actor_id is None:
            query = query.where(SecurityIncident.actor_discord_id.is_(None))
        else:
            query = query.where(SecurityIncident.actor_discord_id == event.actor_id)

        incident = await session.scalar(query.order_by(SecurityIncident.created_at.desc()).limit(1))
        if incident is None:
            actor = str(event.actor_id) if event.actor_id is not None else "unknown"
            incident = SecurityIncident(
                incident_key=f"{event.guild_id}:{actor}:{family}:{event.fingerprint}",
                guild_id=event.guild_id,
                actor_discord_id=event.actor_id,
                incident_type=family,
                severity=severity,
                risk_score=detection.signal.score,
                status="OPEN",
                event_count=1,
                summary=f"{family}: {detection.signal.reason}",
            )
            session.add(incident)
            return

        incident.event_count += 1
        incident.risk_score = max(incident.risk_score, detection.signal.score)
        if _severity_rank(severity) > _severity_rank(incident.severity):
            incident.severity = severity
        incident.summary = (
            f"{family}: {incident.event_count} correlated events; "
            f"latest={detection.signal.reason}"
        )


def _severity_rank(value: str) -> int:
    return {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
        "EMERGENCY": 5,
    }.get(value, 0)
