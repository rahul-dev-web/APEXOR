from __future__ import annotations

import asyncio
import logging

import discord
from discord.ext import tasks
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.ai.threat_analyst import ThreatAnalyst
from app.bot.commands import APEXORCommandTree
from app.bot.recovery_commands import RecoveryGroup
from app.core.config import settings
from app.core.constants import ProtectionState, SecurityEventType
from app.database.session import SessionLocal
from app.models.ai import AIThreatAssessment
from app.models.guild import Guild
from app.models.security import SecurityConfig
from app.security.audit import AuditLogCorrelator, event_from_audit_entry
from app.security.events import Detection, EventCorrelator, SecurityEvent
from app.security.lockdown import LockdownEngine
from app.security.notifications import SecurityNotifier
from app.security.persistence import SecurityPersistence
from app.security.permissions.audit import PermissionAudit
from app.security.permissions.enforcement import PermissionEnforcement
from app.security.protected import ProtectedResourceService
from app.security.protection_runtime import ProtectionRuntime
from app.security.recovery_orchestrator import RecoveryOrchestrator, bind_discord_client
from app.security.setup import GuildAutoSetup
from app.security.snapshots import SnapshotService

logger = logging.getLogger(__name__)


class APEXORClient(discord.Client):
    """Discord Gateway client for APEXOR's deterministic security core."""

    PERMISSION_RECONCILIATION_MINUTES = 5

    def __init__(self) -> None:
        intents = discord.Intents.none()
        intents.guilds = True
        intents.moderation = True
        super().__init__(intents=intents)
        self.tree = APEXORCommandTree(self)
        self.tree.add_command(RecoveryGroup())
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
        if not self.permission_reconciliation.is_running():
            self.permission_reconciliation.start()
        logger.info("APEXOR Discord client setup initialized; recovery worker and permission reconciliation online")

    async def close(self) -> None:
        if self.permission_reconciliation.is_running():
            self.permission_reconciliation.cancel()
        await self.recovery_orchestrator.stop()
        await super().close()

    @tasks.loop(minutes=PERMISSION_RECONCILIATION_MINUTES)
    async def permission_reconciliation(self) -> None:
        """Periodically reconcile permission posture to catch missed Gateway events."""
        for guild in tuple(self.guilds):
            try:
                await self._audit_and_enforce_permissions(guild, reconciliation=True)
            except Exception:
                logger.exception("Permission reconciliation failed for guild=%s", guild.id)

    @permission_reconciliation.before_loop
    async def _wait_for_ready_before_permission_reconciliation(self) -> None:
        await self.wait_until_ready()

    async def on_ready(self) -> None:
        logger.info("APEXOR connected as %s (%s)", self.user, self.user.id if self.user else "unknown")
        logger.info("Connected guilds: %d", len(self.guilds))
        if not self._commands_synced:
            for guild in self.guilds:
                try:
                    # Commands are registered on the global CommandTree. Passing a guild
                    # directly to sync() only syncs commands explicitly scoped to that
                    # guild, which previously produced an empty command list. Copy the
                    # global commands into each guild first so they become available
                    # immediately instead of waiting for Discord's global propagation.
                    self.tree.copy_global_to(guild=guild)
                    synced = await self.tree.sync(guild=guild)
                    logger.info(
                        "Synced APEXOR commands to guild=%s: %s",
                        guild.id,
                        [f"{command.name} ({type(command).__name__})" for command in synced],
                    )
                except discord.HTTPException:
                    logger.exception("Failed to sync APEXOR commands to guild=%s", guild.id)
            self._commands_synced = True
        for guild in self.guilds:
            await self._run_auto_setup(guild)
            await self._audit_and_enforce_permissions(guild)

    async def on_guild_join(self, guild: discord.Guild) -> None:
        logger.info("APEXOR joined guild %s (%s)", guild.name, guild.id)
        try:
            # Keep newly joined guilds consistent with existing guilds: copy the
            # global command definitions before performing a guild-scoped sync.
            self.tree.copy_global_to(guild=guild)
            synced = await self.tree.sync(guild=guild)
            logger.info(
                "Synced APEXOR commands to joined guild=%s: %s",
                guild.id,
                [f"{command.name} ({type(command).__name__})" for command in synced],
            )
        except discord.HTTPException:
            logger.exception("Failed to sync APEXOR commands to joined guild=%s", guild.id)
        await self._run_auto_setup(guild)
        await self._audit_and_enforce_permissions(guild)

    async def on_audit_log_entry_create(self, entry: discord.AuditLogEntry) -> None:
        """Consume Discord's real-time audit-log signal when available."""
        guild = entry.guild
        if guild is None:
            return
        event = event_from_audit_entry(guild, entry)
        if event is None:
            return
        logger.info(
            "Audit Gateway event: guild=%s audit=%s action=%s actor=%s target=%s event=%s",
            guild.id,
            entry.id,
            entry.action,
            event.actor_id,
            event.target_id,
            event.event_type.value,
        )
        await self._process_security_event(event, guild)

    async def on_guild_role_create(self, role: discord.Role) -> None:
        await self._capture_resource(role, "ROLE", source="EVENT_AFTER_CREATE")
        await self._process_security_event(SecurityEvent(guild_id=role.guild.id, event_type=SecurityEventType.ROLE_CREATE, target_id=role.id), role.guild)
        await self._audit_and_enforce_permissions(role.guild)

    async def on_guild_role_update(self, before: discord.Role, after: discord.Role) -> None:
        await self._capture_resource(before, "ROLE", source="EVENT_BEFORE_UPDATE")
        permission_added, permission_removed = self._permission_diff(before.permissions, after.permissions)
        if permission_added:
            logger.warning(
                "Role permission grant detected: guild=%s role=%s added=%s",
                after.guild.id,
                after.id,
                ",".join(permission_added),
            )
        detection = await self._process_security_event(
            SecurityEvent(
                guild_id=after.guild.id,
                event_type=SecurityEventType.ROLE_UPDATE,
                target_id=after.id,
                permission_added=permission_added,
                permission_removed=permission_removed,
            ),
            after.guild,
        )
        await self._capture_after_if_safe(after, "ROLE", detection)
        await self._audit_and_enforce_permissions(after.guild, changed_role=after)

    @staticmethod
    def _permission_diff(before: discord.Permissions, after: discord.Permissions) -> tuple[tuple[str, ...], tuple[str, ...]]:
        added: list[str] = []
        removed: list[str] = []
        for name, enabled_after in after:
            enabled_before = getattr(before, name, False)
            if enabled_after and not enabled_before:
                added.append(name)
            elif enabled_before and not enabled_after:
                removed.append(name)
        return tuple(sorted(added)), tuple(sorted(removed))

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

    async def on_webhooks_update(self, guild: discord.Guild) -> None:
        await self._process_security_event(SecurityEvent(guild_id=guild.id, event_type=SecurityEventType.WEBHOOK_UPDATE), guild)

    async def on_guild_integrations_update(self, guild: discord.Guild) -> None:
        await self._process_security_event(SecurityEvent(guild_id=guild.id, event_type=SecurityEventType.INTEGRATION_UPDATE), guild)

    async def _capture_resource(self, resource, resource_type: str, *, source: str) -> None:
        if SessionLocal is None:
            return
        try:
            async with SessionLocal() as session:
                await self.snapshots.capture_resource(session, resource, resource_type=resource_type, source=source)
                await session.commit()
        except IntegrityError as e:
            # Race condition: multiple concurrent event handlers attempting to capture the same version.
            # Since snapshots are immutable and versioned, duplicate captures are benign and can be ignored.
            if "uq_security_snapshots_version" in str(e):
                logger.debug(
                    "Snapshot version already captured (race condition): guild=%s resource=%s/%s source=%s",
                    getattr(getattr(resource, "guild", resource), "id", "unknown"),
                    resource_type,
                    getattr(resource, "id", "unknown"),
                    source,
                )
            else:
                logger.exception(
                    "Snapshot capture integrity error: guild=%s resource=%s/%s source=%s",
                    getattr(getattr(resource, "guild", resource), "id", "unknown"),
                    resource_type,
                    getattr(resource, "id", "unknown"),
                    source,
                )
        except Exception:
            logger.exception(
                "Snapshot capture failed: guild=%s resource=%s/%s source=%s",
                getattr(getattr(resource, "guild", resource), "id", "unknown"),
                resource_type,
                getattr(resource, "id", "unknown"),
                source,
            )

    async def _capture_after_if_safe(self, resource, resource_type: str, detection: Detection | None) -> None:
        if detection is None or detection.signal.score < 60:
            await self._capture_resource(resource, resource_type, source="EVENT_AFTER_SAFE_UPDATE")

    async def _audit_and_enforce_permissions(self, guild: discord.Guild, *, changed_role: discord.Role | None = None, reconciliation: bool = False) -> None:
        if SessionLocal is None:
            return
        try:
            async with SessionLocal() as session:
                config = await session.scalar(select(SecurityConfig).where(SecurityConfig.guild_id == guild.id))
                if config is None:
                    return
                if not config.auto_permission_audit_enabled and not config.permission_enforcement_enabled:
                    return

            findings = self.permission_audit.audit_guild(guild)
            for finding in findings:
                logger.warning(
                    "Privileged role detected: guild=%s role=%s name=%r severity=%s permissions=%s owner_role=%s",
                    guild.id,
                    finding.role_id,
                    finding.role_name,
                    finding.severity,
                    ",".join(finding.permissions),
                    finding.is_owner_role,
                )

            if not config.permission_enforcement_enabled:
                return

            if changed_role is not None and not reconciliation:
                action = await self.permission_enforcement.enforce_role(guild, changed_role, reason="APEXOR automatic permission enforcement after role update")
                if action.status == "ENFORCED":
                    logger.critical("Permission enforcement: guild=%s role=%s removed=%s", guild.id, action.role_id, ",".join(action.removed_permissions))
                elif action.status == "FAILED":
                    logger.error("Permission enforcement failed: guild=%s role=%s reason=%s", guild.id, action.role_id, action.reason)
                return

            actions = await self.permission_enforcement.enforce_guild(guild, reason="APEXOR permission posture reconciliation")
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
                await self.security_persistence.ensure_guild(session, guild.id, name=guild.name, owner_id=guild.owner_id or 0)
                await session.commit()
        except Exception:
            logger.exception("Failed to persist guild state: guild=%s", guild.id)

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

            match = None
            if event.audit_log_id is None and (config is None or config.audit_correlation_enabled):
                match = await self.audit_correlator.correlate(guild, event)
                if match is not None:
                    event.actor_id = match.actor_id
                    event.audit_log_id = match.audit_log_id

            detection = self.event_correlator.record(event)
            detection.guild = guild
            detection = self.event_correlator.classify(detection)
            await self.security_persistence.persist_event(session, detection)
            await session.commit()

        if detection.signal.score >= 60:
            await self.lockdown.evaluate(guild, detection)
            await self.notifier.notify(guild, detection)
            asyncio.create_task(self._run_ai_analysis(detection, detection.event_log_id))

        return detection
