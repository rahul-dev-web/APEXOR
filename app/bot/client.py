import asyncio
import logging

import discord
from sqlalchemy import select

from app.ai.threat_analyst import ThreatAnalyst
from app.core.config import settings
from app.core.constants import SecurityEventType
from app.database.session import SessionLocal
from app.models.ai import AIThreatAssessment
from app.models.security import SecurityConfig
from app.security.audit import AuditLogCorrelator
from app.security.events import Detection, EventCorrelator, SecurityEvent
from app.security.lockdown import LockdownEngine
from app.security.notifications import SecurityNotifier
from app.security.persistence import SecurityPersistence
from app.security.permissions.audit import PermissionAudit
from app.security.permissions.enforcement import PermissionEnforcement
from app.security.protected import ProtectedResourceService
from app.security.recovery_orchestrator import RecoveryOrchestrator, bind_discord_client
from app.security.setup import GuildAutoSetup
from app.security.snapshots import SnapshotService
from app.bot.commands import APXORCommandTree

logger = logging.getLogger(__name__)


class APXORClient(discord.Client):
    """Discord Gateway client for APXOR's deterministic security core."""

    def __init__(self) -> None:
        intents = discord.Intents.none()
        intents.guilds = True
        super().__init__(intents=intents)
        self.tree = APXORCommandTree(self)
        self._commands_synced = False
        self.permission_audit = PermissionAudit()
        self.permission_enforcement = PermissionEnforcement()
        self.event_correlator = EventCorrelator(window_seconds=10.0)
        self.audit_correlator = AuditLogCorrelator(limit=10)
        self.security_persistence = SecurityPersistence()
        self.protected_resources = ProtectedResourceService()
        self.lockdown = LockdownEngine()
        self.notifier = SecurityNotifier()
        self.auto_setup = GuildAutoSetup()
        self.snapshots = SnapshotService()
        self.recovery_orchestrator = RecoveryOrchestrator()
        self.threat_analyst = ThreatAnalyst()

    async def setup_hook(self) -> None:
        bind_discord_client(self)
        await self.recovery_orchestrator.start()
        logger.info("APXOR Discord client setup initialized; recovery worker online")

    async def close(self) -> None:
        await self.recovery_orchestrator.stop()
        await super().close()

    async def on_ready(self) -> None:
        logger.info("APXOR connected as %s (%s)", self.user, self.user.id if self.user else "unknown")
        logger.info("Connected guilds: %d", len(self.guilds))
        if not self._commands_synced:
            for guild in self.guilds:
                try:
                    await self.tree.sync(guild=guild)
                    logger.info("Synced APXOR commands to guild=%s", guild.id)
                except discord.HTTPException:
                    logger.exception("Failed to sync APXOR commands to guild=%s", guild.id)
            self._commands_synced = True
        for guild in self.guilds:
            await self._audit_and_enforce_permissions(guild)
            await self._run_auto_setup(guild)

    async def on_guild_join(self, guild: discord.Guild) -> None:
        logger.info("APXOR joined guild %s (%s)", guild.name, guild.id)
        try:
            await self.tree.sync(guild=guild)
        except discord.HTTPException:
            logger.exception("Failed to sync APXOR commands to joined guild=%s", guild.id)
        await self._audit_and_enforce_permissions(guild)
        await self._run_auto_setup(guild)

    async def on_guild_role_create(self, role: discord.Role) -> None:
        await self._capture_resource(role, "ROLE", source="EVENT_AFTER_CREATE")
        await self._process_security_event(SecurityEvent(guild_id=role.guild.id, event_type=SecurityEventType.ROLE_CREATE, target_id=role.id), role.guild)
        await self._audit_and_enforce_permissions(role.guild)

    async def on_guild_role_update(self, before: discord.Role, after: discord.Role) -> None:
        await self._capture_resource(before, "ROLE", source="EVENT_BEFORE_UPDATE")
        if before.permissions.value != after.permissions.value:
            logger.warning("Role permission change detected: guild=%s role=%s before=%s after=%s", after.guild.id, after.id, before.permissions.value, after.permissions.value)
        detection = await self._process_security_event(SecurityEvent(guild_id=after.guild.id, event_type=SecurityEventType.ROLE_UPDATE, target_id=after.id), after.guild)
        await self._capture_after_if_safe(after, "ROLE", detection)
        await self._audit_and_enforce_permissions(after.guild, changed_role=after)

    async def on_guild_role_delete(self, role: discord.Role) -> None:
        await self._capture_resource(role, "ROLE", source="EVENT_BEFORE_DELETE")
        logger.warning("Guild role deleted: guild=%s role=%s name=%s", role.guild.id, role.id, role.name)
        await self._process_security_event(SecurityEvent(guild_id=role.guild.id, event_type=SecurityEventType.ROLE_DELETE, target_id=role.id), role.guild)

    async def on_guild_channel_create(self, channel: discord.abc.GuildChannel) -> None:
        await self._capture_resource(channel, "CHANNEL", source="EVENT_AFTER_CREATE")
        await self._process_security_event(SecurityEvent(guild_id=channel.guild.id, event_type=SecurityEventType.CHANNEL_CREATE, target_id=channel.id), channel.guild)

    async def on_guild_channel_update(self, before: discord.abc.GuildChannel, after: discord.abc.GuildChannel) -> None:
        await self._capture_resource(before, "CHANNEL", source="EVENT_BEFORE_UPDATE")
        detection = await self._process_security_event(SecurityEvent(guild_id=after.guild.id, event_type=SecurityEventType.CHANNEL_UPDATE, target_id=after.id), after.guild)
        await self._capture_after_if_safe(after, "CHANNEL", detection)

    async def on_guild_channel_delete(self, channel: discord.abc.GuildChannel) -> None:
        await self._capture_resource(channel, "CHANNEL", source="EVENT_BEFORE_DELETE")
        logger.warning("Guild channel deleted: guild=%s channel=%s name=%s", channel.guild.id, channel.id, channel.name)
        await self._process_security_event(SecurityEvent(guild_id=channel.guild.id, event_type=SecurityEventType.CHANNEL_DELETE, target_id=channel.id), channel.guild)

    async def on_guild_update(self, before: discord.Guild, after: discord.Guild) -> None:
        await self._capture_resource(before, "GUILD", source="EVENT_BEFORE_UPDATE")
        detection = await self._process_security_event(SecurityEvent(guild_id=after.id, event_type=SecurityEventType.GUILD_UPDATE), after)
        await self._capture_after_if_safe(after, "GUILD", detection)

    async def _capture_resource(self, resource, resource_type: str, *, source: str) -> None:
        if SessionLocal is None:
            return
        try:
            async with SessionLocal() as session:
                await self.snapshots.capture_resource(session, resource, resource_type=resource_type, source=source)
                await session.commit()
        except Exception:
            logger.exception("Snapshot capture failed: guild=%s resource=%s/%s source=%s", getattr(getattr(resource, "guild", resource), "id", "unknown"), resource_type, getattr(resource, "id", "unknown"), source)

    async def _capture_after_if_safe(self, resource, resource_type: str, detection: Detection | None) -> None:
        if detection is None or detection.signal.score < 60:
            await self._capture_resource(resource, resource_type, source="EVENT_AFTER_SAFE_UPDATE")

    async def _audit_and_enforce_permissions(self, guild: discord.Guild, *, changed_role: discord.Role | None = None) -> None:
        findings = self.permission_audit.audit_guild(guild)
        for finding in findings:
            logger.warning("Privileged role detected: guild=%s role=%s name=%r severity=%s permissions=%s owner_role=%s", guild.id, finding.role_id, finding.role_name, finding.severity, ",".join(finding.permissions), finding.is_owner_role)

        if SessionLocal is None:
            return
        try:
            async with SessionLocal() as session:
                config = await session.scalar(select(SecurityConfig).where(SecurityConfig.guild_id == guild.id))
                if config is None or not config.permission_enforcement_enabled:
                    return
            if changed_role is not None:
                action = await self.permission_enforcement.enforce_role(guild, changed_role, reason="APXOR automatic permission enforcement after role update")
                if action.status == "ENFORCED":
                    logger.critical("Permission enforcement: guild=%s role=%s removed=%s", guild.id, action.role_id, ",".join(action.removed_permissions))
                elif action.status == "FAILED":
                    logger.error("Permission enforcement failed: guild=%s role=%s reason=%s", guild.id, action.role_id, action.reason)
                return
            actions = await self.permission_enforcement.enforce_guild(guild, reason="APXOR permission posture reconciliation")
            enforced = [a for a in actions if a.status == "ENFORCED"]
            failed = [a for a in actions if a.status == "FAILED"]
            if enforced or failed:
                logger.warning("Permission reconciliation: guild=%s enforced=%d failed=%d", guild.id, len(enforced), len(failed))
        except Exception:
            logger.exception("Permission audit/enforcement failed for guild=%s", guild.id)

    async def _run_auto_setup(self, guild: discord.Guild) -> None:
        if SessionLocal is None:
            logger.warning("Auto-setup skipped: database is not configured (guild=%s)", guild.id)
            return
        try:
            async with SessionLocal() as session:
                config = await session.scalar(select(SecurityConfig).where(SecurityConfig.guild_id == guild.id))
                if config is not None and not config.auto_setup_enabled:
                    logger.info("Auto-setup disabled for guild=%s", guild.id)
                    await self._ensure_guild_record(guild)
                    return
                await self.auto_setup.ensure(session, guild)
        except (discord.Forbidden, discord.HTTPException) as exc:
            logger.error("Auto-setup could not complete for guild=%s; verify bot permissions and role hierarchy: %s", guild.id, exc)
            await self._ensure_guild_record(guild)
        except Exception:
            logger.exception("Auto-setup failed for guild=%s", guild.id)
            await self._ensure_guild_record(guild)

    async def _ensure_guild_record(self, guild: discord.Guild) -> None:
        if SessionLocal is None:
            return
        try:
            async with SessionLocal() as session:
                await self.security_persistence.ensure_guild(session, guild.id, name=guild.name, owner_id=guild.owner_id)
                await session.commit()
        except Exception:
            logger.exception("Failed to persist guild state: guild=%s", guild.id)

    async def _persist_detection(self, detection: Detection) -> int | None:
        if SessionLocal is None:
            return None
        try:
            guild = self.get_guild(detection.event.guild_id)
            async with SessionLocal() as session:
                await self.security_persistence.ensure_guild(session, detection.event.guild_id, name=guild.name if guild else "Unknown Guild", owner_id=guild.owner_id if guild else 0)
                return await self.security_persistence.record(session, detection)
        except Exception:
            logger.exception("Security persistence failed; detection remains in-memory: guild=%s fingerprint=%s", detection.event.guild_id, detection.event.fingerprint)
            return None

    async def _run_ai_analysis(self, detection: Detection, event_log_id: int | None) -> None:
        """Run advisory AI analysis outside the critical security path."""
        if not self.threat_analyst.enabled or SessionLocal is None:
            return
        result = await self.threat_analyst.analyze(detection)
        if result is None:
            return

        assessment, input_hash, latency_ms = result
        try:
            async with SessionLocal() as session:
                session.add(
                    AIThreatAssessment(
                        guild_id=detection.event.guild_id,
                        event_log_id=event_log_id,
                        model=settings.groq_model,
                        prompt_version="threat-analyst-v1",
                        input_hash=input_hash,
                        classification=assessment.classification,
                        confidence=assessment.confidence,
                        reason=assessment.reason,
                        recommended_action=assessment.recommended_action,
                        notify_owner=assessment.notify_owner,
                        latency_ms=round(latency_ms),
                    )
                )
                await session.commit()
        except Exception:
            logger.exception("Failed to persist Groq threat assessment: guild=%s event=%s", detection.event.guild_id, event_log_id)

    async def _process_security_event(self, event: SecurityEvent, guild: discord.Guild) -> Detection | None:
        if SessionLocal is None:
            logger.warning("Security event skipped because database is not configured: guild=%s", event.guild_id)
            return None

        async with SessionLocal() as session:
            config = await session.scalar(select(SecurityConfig).where(SecurityConfig.guild_id == event.guild_id))
            if config is not None and not config.anti_nuke_enabled:
                return None

            match = await self.audit_correlator.correlate(guild, event) if config is None or config.audit_correlation_enabled else None
            if match is not None:
                event = SecurityEvent(guild_id=event.guild_id, event_type=event.event_type, target_id=event.target_id, actor_id=match.actor_id, protected_target=event.protected_target, audit_log_id=match.audit_log_id, event_id=event.event_id, timestamp=event.timestamp)
                logger.info("Audit correlation: guild=%s audit=%s actor=%s action=%s target=%s", event.guild_id, match.audit_log_id, match.actor_id, match.action, event.target_id)

            if event.target_id is not None:
                protected = await self.protected_resources.is_protected_target(session, guild_id=event.guild_id, target_id=event.target_id, event_type=event.event_type.value)
                if protected and not event.protected_target:
                    event = SecurityEvent(guild_id=event.guild_id, event_type=event.event_type, target_id=event.target_id, actor_id=event.actor_id, protected_target=True, audit_log_id=event.audit_log_id, event_id=event.event_id, timestamp=event.timestamp)

            detection = self.event_correlator.process(event)
            if detection.velocity_count == 0:
                logger.debug("Duplicate security event suppressed: %s", event.fingerprint)
                return None

            event_log_id = await self.security_persistence.ensure_guild(session, event.guild_id, name=guild.name, owner_id=guild.owner_id)
            del event_log_id
            persisted_event_id = await self.security_persistence.record(session, detection)
            logger.info("Security event: guild=%s type=%s actor=%s target=%s risk=%d velocity=%d/%ss reason=%s", event.guild_id, event.event_type.value, event.actor_id, event.target_id, detection.signal.score, detection.velocity_count, detection.velocity_window_seconds, detection.signal.reason)

            high_threshold = config.risk_threshold_high if config else 60
            critical_threshold = config.risk_threshold_critical if config else 80
            emergency_threshold = config.risk_threshold_emergency if config else 95
            lockdown_threshold = critical_threshold
            if event.protected_target and event.event_type in {SecurityEventType.CHANNEL_DELETE, SecurityEventType.ROLE_DELETE, SecurityEventType.ROLE_UPDATE}:
                lockdown_threshold = min(lockdown_threshold, high_threshold)

            # AI is deliberately launched after persistence but does not block
            # containment, notification, or recovery below.
            if detection.signal.score >= high_threshold:
                asyncio.create_task(self._run_ai_analysis(detection, persisted_event_id))

            if detection.signal.score >= lockdown_threshold and (config is None or config.lockdown_enabled):
                actions = await self.lockdown.enter_lockdown(session, guild, actor_id=event.actor_id, event_log_id=persisted_event_id)
                logger.critical("APXOR LOCKDOWN: guild=%s actor=%s risk=%d actions=%s", event.guild_id, event.actor_id, detection.signal.score, actions)

            severity = None
            if detection.signal.score >= emergency_threshold:
                severity = "EMERGENCY"
            elif detection.signal.score >= critical_threshold:
                severity = "CRITICAL"
            elif detection.signal.score >= high_threshold:
                severity = "HIGH"

            if severity is not None:
                await self.notifier.notify(session, guild, severity=severity, event_type=event.event_type.value, actor_id=event.actor_id, target_id=event.target_id, risk_score=detection.signal.score, reason=detection.signal.reason, owner_dm_enabled=config.owner_dm_enabled if config else True, notification_enabled=config.notification_enabled if config else True)

            if (config is None or config.recovery_enabled) and event.event_type in {SecurityEventType.CHANNEL_DELETE, SecurityEventType.ROLE_DELETE} and detection.signal.score >= high_threshold:
                resource_type = "CHANNEL" if event.event_type == SecurityEventType.CHANNEL_DELETE else "ROLE"
                priority = 10 if event.protected_target else 50
                queued = await self.recovery_orchestrator.enqueue(guild_id=event.guild_id, resource_type=resource_type, resource_id=event.target_id or 0, reason=f"Automatic recovery after {event.event_type.value}; risk={detection.signal.score}; actor={event.actor_id}", priority=priority)
                if not queued:
                    logger.critical("RECOVERY QUEUE REJECTED: guild=%s resource=%s/%s risk=%s", event.guild_id, resource_type, event.target_id, detection.signal.score)

            return detection

    async def start_bot(self) -> None:
        if not settings.discord_token:
            raise RuntimeError("DISCORD_TOKEN is not configured")
        await self.start(settings.discord_token)
