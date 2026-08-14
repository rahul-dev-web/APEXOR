import logging

import discord
from sqlalchemy import select

from app.core.config import settings
from app.core.constants import SecurityEventType
from app.database.session import SessionLocal
from app.models.security import SecurityConfig
from app.security.audit import AuditLogCorrelator
from app.security.events import EventCorrelator, SecurityEvent
from app.security.lockdown import LockdownEngine
from app.security.persistence import SecurityPersistence
from app.security.permissions.audit import PermissionAudit
from app.security.protected import ProtectedResourceService
from app.security.recovery_orchestrator import RecoveryOrchestrator, bind_discord_client
from app.security.setup import GuildAutoSetup
from app.security.snapshots import SnapshotService

logger = logging.getLogger(__name__)


class APXORClient(discord.Client):
    """Discord Gateway client for APXOR's deterministic security core."""

    def __init__(self) -> None:
        intents = discord.Intents.none()
        intents.guilds = True

        super().__init__(intents=intents)
        self.permission_audit = PermissionAudit()
        self.event_correlator = EventCorrelator(window_seconds=10.0)
        self.audit_correlator = AuditLogCorrelator(limit=10)
        self.security_persistence = SecurityPersistence()
        self.protected_resources = ProtectedResourceService()
        self.lockdown = LockdownEngine()
        self.auto_setup = GuildAutoSetup()
        self.snapshots = SnapshotService()
        self.recovery_orchestrator = RecoveryOrchestrator()
        self._recovery_bound = False

    async def setup_hook(self) -> None:
        bind_discord_client(self)
        self._recovery_bound = True
        await self.recovery_orchestrator.start()
        logger.info("APXOR Discord client setup initialized; recovery worker online")

    async def close(self) -> None:
        await self.recovery_orchestrator.stop()
        await super().close()

    async def on_ready(self) -> None:
        logger.info(
            "APXOR connected as %s (%s)",
            self.user,
            self.user.id if self.user else "unknown",
        )
        logger.info("Connected guilds: %d", len(self.guilds))

        for guild in self.guilds:
            self._log_permission_findings(guild)
            await self._run_auto_setup(guild)

    async def on_guild_join(self, guild: discord.Guild) -> None:
        logger.info("APXOR joined guild %s (%s)", guild.name, guild.id)
        self._log_permission_findings(guild)
        await self._run_auto_setup(guild)

    async def on_guild_role_create(self, role: discord.Role) -> None:
        await self._capture_resource(role, "ROLE", source="EVENT_AFTER_CREATE")
        await self._process_security_event(
            SecurityEvent(guild_id=role.guild.id, event_type=SecurityEventType.ROLE_CREATE, target_id=role.id),
            role.guild,
        )
        self._log_permission_findings(role.guild)

    async def on_guild_role_update(self, before: discord.Role, after: discord.Role) -> None:
        # Snapshot the known-good state BEFORE processing the update. If the
        # update is malicious, recovery can reconstruct the previous state.
        await self._capture_resource(before, "ROLE", source="EVENT_BEFORE_UPDATE")
        if before.permissions.value != after.permissions.value:
            logger.warning(
                "Role permission change detected: guild=%s role=%s before=%s after=%s",
                after.guild.id, after.id, before.permissions.value, after.permissions.value,
            )
        await self._process_security_event(
            SecurityEvent(guild_id=after.guild.id, event_type=SecurityEventType.ROLE_UPDATE, target_id=after.id),
            after.guild,
        )
        self._log_permission_findings(after.guild)

    async def on_guild_role_delete(self, role: discord.Role) -> None:
        # The delete event still carries the last known role object. Persist it
        # before detection so the recovery queue has a current source snapshot.
        await self._capture_resource(role, "ROLE", source="EVENT_BEFORE_DELETE")
        logger.warning("Guild role deleted: guild=%s role=%s name=%s", role.guild.id, role.id, role.name)
        await self._process_security_event(
            SecurityEvent(guild_id=role.guild.id, event_type=SecurityEventType.ROLE_DELETE, target_id=role.id),
            role.guild,
        )

    async def on_guild_channel_create(self, channel: discord.abc.GuildChannel) -> None:
        await self._capture_resource(channel, "CHANNEL", source="EVENT_AFTER_CREATE")
        await self._process_security_event(
            SecurityEvent(guild_id=channel.guild.id, event_type=SecurityEventType.CHANNEL_CREATE, target_id=channel.id),
            channel.guild,
        )

    async def on_guild_channel_update(self, before: discord.abc.GuildChannel, after: discord.abc.GuildChannel) -> None:
        await self._capture_resource(before, "CHANNEL", source="EVENT_BEFORE_UPDATE")
        await self._process_security_event(
            SecurityEvent(guild_id=after.guild.id, event_type=SecurityEventType.CHANNEL_UPDATE, target_id=after.id),
            after.guild,
        )

    async def on_guild_channel_delete(self, channel: discord.abc.GuildChannel) -> None:
        await self._capture_resource(channel, "CHANNEL", source="EVENT_BEFORE_DELETE")
        logger.warning("Guild channel deleted: guild=%s channel=%s name=%s", channel.guild.id, channel.id, channel.name)
        await self._process_security_event(
            SecurityEvent(guild_id=channel.guild.id, event_type=SecurityEventType.CHANNEL_DELETE, target_id=channel.id),
            channel.guild,
        )

    async def on_guild_update(self, before: discord.Guild, after: discord.Guild) -> None:
        await self._capture_resource(before, "GUILD", source="EVENT_BEFORE_UPDATE")
        await self._process_security_event(
            SecurityEvent(guild_id=after.id, event_type=SecurityEventType.GUILD_UPDATE),
            after,
        )

    async def _capture_resource(self, resource, resource_type: str, *, source: str) -> None:
        """Persist a resource snapshot without blocking the security decision path."""
        if SessionLocal is None:
            return
        try:
            async with SessionLocal() as session:
                await self.snapshots.capture_resource(
                    session,
                    resource,
                    resource_type=resource_type,
                    source=source,
                )
                await session.commit()
        except Exception:
            logger.exception(
                "Snapshot capture failed: guild=%s resource=%s/%s source=%s",
                getattr(getattr(resource, "guild", resource), "id", "unknown"),
                resource_type,
                getattr(resource, "id", "unknown"),
                source,
            )

    async def _run_auto_setup(self, guild: discord.Guild) -> None:
        if SessionLocal is None:
            logger.warning("Auto-setup skipped: database is not configured (guild=%s)", guild.id)
            return
        try:
            async with SessionLocal() as session:
                config = await session.scalar(
                    select(SecurityConfig).where(SecurityConfig.guild_id == guild.id)
                )
                if config is not None and not config.auto_setup_enabled:
                    logger.info("Auto-setup disabled for guild=%s", guild.id)
                    await self._ensure_guild_record(guild)
                    return
                await self.auto_setup.ensure(session, guild)
        except (discord.Forbidden, discord.HTTPException) as exc:
            logger.error(
                "Auto-setup could not complete for guild=%s; verify bot permissions and role hierarchy: %s",
                guild.id,
                exc,
            )
            await self._ensure_guild_record(guild)
        except Exception:
            logger.exception("Auto-setup failed for guild=%s", guild.id)
            await self._ensure_guild_record(guild)

    async def _ensure_guild_record(self, guild: discord.Guild) -> None:
        if SessionLocal is None:
            return
        try:
            async with SessionLocal() as session:
                await self.security_persistence.ensure_guild(
                    session, guild.id, name=guild.name, owner_id=guild.owner_id,
                )
                await session.commit()
        except Exception:
            logger.exception("Failed to persist guild state: guild=%s", guild.id)

    async def _persist_detection(self, detection) -> int | None:
        if SessionLocal is None:
            return None
        try:
            guild = self.get_guild(detection.event.guild_id)
            async with SessionLocal() as session:
                await self.security_persistence.ensure_guild(
                    session,
                    detection.event.guild_id,
                    name=guild.name if guild else "Unknown Guild",
                    owner_id=guild.owner_id if guild else 0,
                )
                return await self.security_persistence.record(session, detection)
        except Exception:
            logger.exception(
                "Security persistence failed; detection remains in-memory: guild=%s fingerprint=%s",
                detection.event.guild_id, detection.event.fingerprint,
            )
            return None

    async def _process_security_event(self, event: SecurityEvent, guild: discord.Guild) -> None:
        """Correlate, enrich, score, persist, contain, and recover a security event."""
        match = await self.audit_correlator.correlate(guild, event)
        if match is not None:
            event = SecurityEvent(
                guild_id=event.guild_id,
                event_type=event.event_type,
                target_id=event.target_id,
                actor_id=match.actor_id,
                protected_target=event.protected_target,
                audit_log_id=match.audit_log_id,
                event_id=event.event_id,
                timestamp=event.timestamp,
            )
            logger.info(
                "Audit correlation: guild=%s audit=%s actor=%s action=%s target=%s",
                event.guild_id, match.audit_log_id, match.actor_id, match.action, event.target_id,
            )

        if SessionLocal is not None and event.target_id is not None:
            try:
                async with SessionLocal() as session:
                    protected = await self.protected_resources.is_protected_target(
                        session,
                        guild_id=event.guild_id,
                        target_id=event.target_id,
                        event_type=event.event_type.value,
                    )
                if protected and not event.protected_target:
                    event = SecurityEvent(
                        guild_id=event.guild_id,
                        event_type=event.event_type,
                        target_id=event.target_id,
                        actor_id=event.actor_id,
                        protected_target=True,
                        audit_log_id=event.audit_log_id,
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                    )
            except Exception:
                logger.exception("Protected-resource lookup failed: guild=%s target=%s", guild.id, event.target_id)

        detection = self.event_correlator.process(event)
        if detection.velocity_count == 0:
            logger.debug("Duplicate security event suppressed: %s", event.fingerprint)
            return

        event_log_id = await self._persist_detection(detection)

        logger.info(
            "Security event: guild=%s type=%s actor=%s target=%s risk=%d velocity=%d/%ss reason=%s",
            event.guild_id, event.event_type.value, event.actor_id, event.target_id,
            detection.signal.score, detection.velocity_count,
            detection.velocity_window_seconds, detection.signal.reason,
        )

        should_lockdown = detection.signal.score >= 80 or (
            event.protected_target
            and event.event_type in {
                SecurityEventType.CHANNEL_DELETE,
                SecurityEventType.ROLE_DELETE,
                SecurityEventType.ROLE_UPDATE,
            }
            and detection.signal.score >= 60
        )

        if should_lockdown and SessionLocal is not None:
            try:
                async with SessionLocal() as session:
                    config = await session.scalar(
                        select(SecurityConfig).where(SecurityConfig.guild_id == event.guild_id)
                    )
                    if config is None or config.lockdown_enabled:
                        actions = await self.lockdown.enter_lockdown(
                            session,
                            guild,
                            actor_id=event.actor_id,
                            event_log_id=event_log_id,
                        )
                        logger.critical(
                            "APXOR LOCKDOWN: guild=%s actor=%s risk=%d actions=%s",
                            event.guild_id, event.actor_id, detection.signal.score, actions,
                        )
            except Exception:
                logger.exception("Lockdown execution failed: guild=%s", event.guild_id)

        if event.event_type in {SecurityEventType.CHANNEL_DELETE, SecurityEventType.ROLE_DELETE} and detection.signal.score >= 60:
            resource_type = "CHANNEL" if event.event_type == SecurityEventType.CHANNEL_DELETE else "ROLE"
            priority = 10 if event.protected_target else 50
            queued = await self.recovery_orchestrator.enqueue(
                guild_id=event.guild_id,
                resource_type=resource_type,
                resource_id=event.target_id or 0,
                reason=(
                    f"Automatic recovery after {event.event_type.value}; "
                    f"risk={detection.signal.score}; actor={event.actor_id}"
                ),
                priority=priority,
            )
            if not queued:
                logger.critical(
                    "RECOVERY QUEUE REJECTED: guild=%s resource=%s/%s risk=%s",
                    event.guild_id, resource_type, event.target_id, detection.signal.score,
                )

        if detection.signal.score >= 80:
            logger.critical(
                "CRITICAL security pattern detected: guild=%s actor=%s type=%s target=%s risk=%d",
                event.guild_id, event.actor_id, event.event_type.value, event.target_id, detection.signal.score,
            )
        elif detection.signal.score >= 60:
            logger.warning(
                "HIGH security pattern detected: guild=%s actor=%s type=%s target=%s risk=%d",
                event.guild_id, event.actor_id, event.event_type.value, event.target_id, detection.signal.score,
            )

    def _log_permission_findings(self, guild: discord.Guild) -> None:
        for finding in self.permission_audit.audit_guild(guild):
            logger.warning(
                "Privileged role detected: guild=%s role=%s name=%r severity=%s permissions=%s owner_role=%s",
                guild.id, finding.role_id, finding.role_name, finding.severity,
                ",".join(finding.permissions), finding.is_owner_role,
            )

    async def start_bot(self) -> None:
        if not settings.discord_token:
            raise RuntimeError("DISCORD_TOKEN is not configured")
        await self.start(settings.discord_token)
