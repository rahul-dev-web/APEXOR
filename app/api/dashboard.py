from __future__ import annotations

from datetime import datetime
import secrets

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import desc, select

from app.api.dashboard_auth import require_dashboard_guild_access, require_dashboard_mutation_access
from app.core.config import settings
from app.core.constants import Capability
from app.database.session import SessionLocal
from app.models.admin_changes import AdminChange
from app.models.ai import AIThreatAssessment
from app.models.capabilities import UserCapability
from app.models.events import SecurityEventLog, SecurityIncident
from app.models.guild import Guild
from app.models.recovery import RecoveryAction
from app.models.security import SecurityConfig
from app.models.snapshots import SecuritySnapshot
from app.security.authorization import AuthorizationService

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])
authorization = AuthorizationService()


class CapabilityMutation(BaseModel):
    discord_user_id: int
    capability: Capability
    expires_at: datetime | None = None


async def require_dashboard_key(x_apxor_dashboard_key: str | None = Header(default=None)) -> None:
    """Legacy service-to-service authentication for non-guild dashboard endpoints."""
    configured = settings.dashboard_api_key
    if not configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Dashboard API authentication is not configured.",
        )
    if not x_apxor_dashboard_key or not secrets.compare_digest(x_apxor_dashboard_key, configured):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid dashboard credentials.")


async def _guild_or_404(session, guild_id: int) -> Guild:
    guild = await session.scalar(select(Guild).where(Guild.discord_guild_id == guild_id))
    if guild is None:
        raise HTTPException(status_code=404, detail="Guild is not registered with APXOR.")
    return guild


@router.get("/guilds/{guild_id}/security", dependencies=[Depends(require_dashboard_guild_access)])
async def security_overview(guild_id: int) -> dict:
    if SessionLocal is None:
        raise HTTPException(status_code=503, detail="Database is unavailable.")
    async with SessionLocal() as session:
        guild = await _guild_or_404(session, guild_id)
        config = await session.scalar(select(SecurityConfig).where(SecurityConfig.guild_id == guild.id))
        return {
            "guild_id": guild.discord_guild_id,
            "name": guild.name,
            "owner_id": guild.owner_discord_id,
            "protection_state": guild.protection_state,
            "protection_score": guild.protection_score,
            "is_active": guild.is_active,
            "last_seen_at": guild.last_seen_at,
            "security": None if config is None else {
                "anti_nuke_enabled": config.anti_nuke_enabled,
                "permission_enforcement_enabled": config.permission_enforcement_enabled,
                "audit_correlation_enabled": config.audit_correlation_enabled,
                "snapshot_enabled": config.snapshot_enabled,
                "recovery_enabled": config.recovery_enabled,
                "lockdown_enabled": config.lockdown_enabled,
                "notification_enabled": config.notification_enabled,
                "owner_dm_enabled": config.owner_dm_enabled,
            },
        }


@router.get("/guilds/{guild_id}/capabilities", dependencies=[Depends(require_dashboard_guild_access)])
async def capabilities(guild_id: int, limit: int = 200) -> list[dict]:
    """Return active and inactive APXOR capability grants for dashboard management."""
    if SessionLocal is None:
        raise HTTPException(status_code=503, detail="Database is unavailable.")
    limit = max(1, min(limit, 500))
    async with SessionLocal() as session:
        guild = await _guild_or_404(session, guild_id)
        rows = (await session.scalars(
            select(UserCapability)
            .where(UserCapability.guild_id == guild.id)
            .order_by(desc(UserCapability.created_at))
            .limit(limit)
        )).all()
        return [
            {
                "id": row.id,
                "discord_user_id": row.discord_user_id,
                "capability": row.capability,
                "enabled": row.enabled,
                "granted_by_discord_id": row.granted_by_discord_id,
                "expires_at": row.expires_at,
                "created_at": row.created_at,
            }
            for row in rows
        ]


@router.get("/guilds/{guild_id}/admin-changes", dependencies=[Depends(require_dashboard_guild_access)])
async def admin_changes(guild_id: int, limit: int = 50) -> list[dict]:
    """Return the control-plane audit trail for dashboard/security administration."""
    if SessionLocal is None:
        raise HTTPException(status_code=503, detail="Database is unavailable.")
    limit = max(1, min(limit, 200))
    async with SessionLocal() as session:
        guild = await _guild_or_404(session, guild_id)
        rows = (await session.scalars(
            select(AdminChange)
            .where(AdminChange.guild_id == guild.id)
            .order_by(desc(AdminChange.created_at))
            .limit(limit)
        )).all()
        return [
            {
                "id": row.id,
                "actor_id": row.actor_discord_id,
                "action": row.action,
                "target_id": row.target_discord_id,
                "capability": row.capability,
                "metadata": row.metadata_json,
                "created_at": row.created_at,
            }
            for row in rows
        ]


@router.post("/guilds/{guild_id}/capabilities/grant")
async def grant_capability(
    guild_id: int,
    payload: CapabilityMutation,
    principal=Depends(require_dashboard_mutation_access),
) -> dict:
    """Grant an APXOR capability using owner/security-manager authority plus CSRF."""
    if SessionLocal is None:
        raise HTTPException(status_code=503, detail="Database is unavailable.")
    async with SessionLocal() as session:
        await _guild_or_404(session, guild_id)
        if not await authorization.is_allowed(
            session,
            guild_id=guild_id,
            discord_user_id=principal.user_id,
            capability=Capability.SECURITY_MANAGE,
        ):
            raise HTTPException(status_code=403, detail="SECURITY_MANAGE capability required.")
        if payload.discord_user_id <= 0:
            raise HTTPException(status_code=422, detail="discord_user_id must be a positive Discord snowflake.")
        if payload.expires_at is not None and payload.expires_at <= datetime.now(payload.expires_at.tzinfo):
            raise HTTPException(status_code=422, detail="expires_at must be in the future.")

        grant = await authorization.grant(
            session,
            guild_id=guild_id,
            discord_user_id=payload.discord_user_id,
            capability=payload.capability,
            granted_by_discord_id=principal.user_id,
            expires_at=payload.expires_at,
        )
        await session.commit()
        return {
            "id": grant.id,
            "discord_user_id": grant.discord_user_id,
            "capability": grant.capability,
            "enabled": grant.enabled,
            "granted_by_discord_id": grant.granted_by_discord_id,
            "expires_at": grant.expires_at,
        }


@router.post("/guilds/{guild_id}/capabilities/revoke")
async def revoke_capability(
    guild_id: int,
    payload: CapabilityMutation,
    principal=Depends(require_dashboard_mutation_access),
) -> dict[str, bool]:
    """Disable an APXOR capability grant; owner/security-manager authority is required."""
    if SessionLocal is None:
        raise HTTPException(status_code=503, detail="Database is unavailable.")
    async with SessionLocal() as session:
        await _guild_or_404(session, guild_id)
        if not await authorization.is_allowed(
            session,
            guild_id=guild_id,
            discord_user_id=principal.user_id,
            capability=Capability.SECURITY_MANAGE,
        ):
            raise HTTPException(status_code=403, detail="SECURITY_MANAGE capability required.")
        revoked = await authorization.revoke(
            session,
            guild_id=guild_id,
            discord_user_id=payload.discord_user_id,
            capability=payload.capability,
            revoked_by_discord_id=principal.user_id,
        )
        await session.commit()
        return {"revoked": revoked}


@router.get("/guilds/{guild_id}/incidents", dependencies=[Depends(require_dashboard_guild_access)])
async def incidents(guild_id: int, limit: int = 25) -> list[dict]:
    if SessionLocal is None:
        raise HTTPException(status_code=503, detail="Database is unavailable.")
    limit = max(1, min(limit, 100))
    async with SessionLocal() as session:
        guild = await _guild_or_404(session, guild_id)
        rows = (await session.scalars(
            select(SecurityIncident).where(SecurityIncident.guild_id == guild.id).order_by(desc(SecurityIncident.created_at)).limit(limit)
        )).all()
        return [
            {"id": row.id, "incident_key": row.incident_key, "actor_id": row.actor_discord_id, "incident_type": row.incident_type, "severity": row.severity, "risk_score": row.risk_score, "status": row.status, "event_count": row.event_count, "summary": row.summary, "created_at": row.created_at, "resolved_at": row.resolved_at}
            for row in rows
        ]


@router.get("/guilds/{guild_id}/events", dependencies=[Depends(require_dashboard_guild_access)])
async def events(guild_id: int, limit: int = 50) -> list[dict]:
    if SessionLocal is None:
        raise HTTPException(status_code=503, detail="Database is unavailable.")
    limit = max(1, min(limit, 200))
    async with SessionLocal() as session:
        guild = await _guild_or_404(session, guild_id)
        rows = (await session.scalars(
            select(SecurityEventLog).where(SecurityEventLog.guild_id == guild.id).order_by(desc(SecurityEventLog.created_at)).limit(limit)
        )).all()
        return [
            {"id": row.id, "fingerprint": row.fingerprint, "event_type": row.event_type, "severity": row.severity, "actor_id": row.actor_discord_id, "target_id": row.target_discord_id, "audit_log_id": row.audit_log_id, "risk_score": row.risk_score, "velocity_count": row.velocity_count, "status": row.status, "action_taken": row.action_taken, "reason": row.reason, "created_at": row.created_at}
            for row in rows
        ]


@router.get("/guilds/{guild_id}/ai", dependencies=[Depends(require_dashboard_guild_access)])
async def ai_assessments(guild_id: int, limit: int = 25) -> list[dict]:
    if SessionLocal is None:
        raise HTTPException(status_code=503, detail="Database is unavailable.")
    limit = max(1, min(limit, 100))
    async with SessionLocal() as session:
        guild = await _guild_or_404(session, guild_id)
        rows = (await session.scalars(
            select(AIThreatAssessment).where(AIThreatAssessment.guild_id == guild.id).order_by(desc(AIThreatAssessment.created_at)).limit(limit)
        )).all()
        return [
            {"id": row.id, "event_log_id": row.event_log_id, "model": row.model, "prompt_version": row.prompt_version, "classification": row.classification, "confidence": row.confidence, "reason": row.reason, "recommended_action": row.recommended_action, "notify_owner": row.notify_owner, "latency_ms": row.latency_ms, "created_at": row.created_at}
            for row in rows
        ]


@router.get("/guilds/{guild_id}/recovery", dependencies=[Depends(require_dashboard_guild_access)])
async def recovery(guild_id: int, limit: int = 50) -> list[dict]:
    if SessionLocal is None:
        raise HTTPException(status_code=503, detail="Database is unavailable.")
    limit = max(1, min(limit, 200))
    async with SessionLocal() as session:
        guild = await _guild_or_404(session, guild_id)
        rows = (await session.scalars(
            select(RecoveryAction).where(RecoveryAction.guild_id == guild.id).order_by(desc(RecoveryAction.created_at)).limit(limit)
        )).all()
        return [
            {"id": row.id, "resource_type": row.resource_type, "original_resource_id": row.original_resource_id, "restored_resource_id": row.restored_resource_id, "snapshot_id": row.snapshot_id, "status": row.status, "reason": row.reason, "error": row.error, "created_at": row.created_at, "completed_at": row.completed_at}
            for row in rows
        ]


@router.get("/guilds/{guild_id}/snapshots", dependencies=[Depends(require_dashboard_guild_access)])
async def snapshots(guild_id: int, limit: int = 50) -> list[dict]:
    if SessionLocal is None:
        raise HTTPException(status_code=503, detail="Database is unavailable.")
    limit = max(1, min(limit, 200))
    async with SessionLocal() as session:
        guild = await _guild_or_404(session, guild_id)
        rows = (await session.scalars(
            select(SecuritySnapshot).where(SecuritySnapshot.guild_id == guild.id).order_by(desc(SecuritySnapshot.created_at)).limit(limit)
        )).all()
        return [
            {"id": row.id, "snapshot_key": row.snapshot_key, "resource_type": row.resource_type, "resource_id": row.resource_id, "version": row.version, "source": row.source, "created_at": row.created_at}
            for row in rows
        ]


@router.get("/health", dependencies=[Depends(require_dashboard_key)])
async def dashboard_health() -> dict[str, str]:
    return {"status": "ok", "service": "apxor-dashboard-api"}
