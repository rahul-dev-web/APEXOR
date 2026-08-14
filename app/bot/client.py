import logging

import discord

from app.core.config import settings
from app.core.constants import SecurityEventType
from app.database.session import SessionLocal
from app.security.audit import AuditLogCorrelator
from app.security.events import EventCorrelator, SecurityEvent
from app.security.persistence import SecurityPersistence
from app.security.permissions.audit import PermissionAudit

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

    async def setup_hook(self) -> None:
        logger.info("APXOR Discord client setup initialized")

    async def on_ready(self) -> None:
        logger.info(
            "APXOR connected as %s (%s)",
            self.user,
            self.user.id if self.user else "unknown",
        )
        logger.info("Connected guilds: %d", len(self.guilds))

        for guild in self.guilds:
            self._log_permission_findings(guild)
            await self._ensure_guild_record(guild)

    async def on_guild_join(self, guild: discord.Guild) -> None:
        logger.info("APXOR joined guild %s (%s)", guild.name, guild.id)
        self._log_permission_findings(guild)
        await self._ensure_guild_record(guild)

    async def on_guild_role_create(self, role: discord.Role) -> None:
        await self._process_security_event(
            SecurityEvent(
                guild_id=role.guild.id,
                event_type=SecurityEventType.ROLE_CREATE,
                target_id=role.id,
            ),
            role.guild,
        )
        self._log_permission_findings(role.guild)

    async def on_guild_role_update(self, before: discord.Role, after: discord.Role) -> None:
        if before.permissions.value != after.permissions.value:
            logger.warning(
                "Role permission change detected: guild=%s role=%s before=%s after=%s",
                after.guild.id,
                after.id,
                before.permissions.value,
                after.permissions.value,
            )
        await self._process_security_event(
            SecurityEvent(
                guild_id=after.guild.id,
                event_type=SecurityEventType.ROLE_UPDATE,
                target_id=after.id,
            ),
            after.guild,
        )
        self._log_permission_findings(after.guild)

    async def on_guild_role_delete(self, role: discord.Role) -> None:
        logger.warning(
            "Guild role deleted: guild=%s role=%s name=%s",
            role.guild.id,
            role.id,
            role.name,
        )
        await self._process_security_event(
            SecurityEvent(
                guild_id=role.guild.id,
                event_type=SecurityEventType.ROLE_DELETE,
                target_id=role.id,
            ),
            role.guild,
        )

    async def on_guild_channel_create(self, channel: discord.abc.GuildChannel) -> None:
        await self._process_security_event(
            SecurityEvent(
                guild_id=channel.guild.id,
                event_type=SecurityEventType.CHANNEL_CREATE,
                target_id=channel.id,
            ),
            channel.guild,
        )

    async def on_guild_channel_update(
        self,
        before: discord.abc.GuildChannel,
        after: discord.abc.GuildChannel,
    ) -> None:
        await self._process_security_event(
            SecurityEvent(
                guild_id=after.guild.id,
                event_type=SecurityEventType.CHANNEL_UPDATE,
                target_id=after.id,
            ),
            after.guild,
        )

    async def on_guild_channel_delete(self, channel: discord.abc.GuildChannel) -> None:
        logger.warning(
            "Guild channel deleted: guild=%s channel=%s name=%s",
            channel.guild.id,
            channel.id,
            channel.name,
        )
        await self._process_security_event(
            SecurityEvent(
                guild_id=channel.guild.id,
                event_type=SecurityEventType.CHANNEL_DELETE,
                target_id=channel.id,
            ),
            channel.guild,
        )

    async def on_guild_update(self, before: discord.Guild, after: discord.Guild) -> None:
        await self._process_security_event(
            SecurityEvent(
                guild_id=after.id,
                event_type=SecurityEventType.GUILD_UPDATE,
            ),
            after,
        )

    async def _ensure_guild_record(self, guild: discord.Guild) -> None:
        if SessionLocal is None:
            return
        try:
            async with SessionLocal() as session:
                await self.security_persistence.ensure_guild(
                    session,
                    guild.id,
                    name=guild.name,
                    owner_id=guild.owner_id,
                )
                await session.commit()
        except Exception:
            logger.exception("Failed to persist guild state: guild=%s", guild.id)

    async def _persist_detection(self, detection) -> None:
        if SessionLocal is None:
            return
        try:
            async with SessionLocal() as session:
                await self.security_persistence.ensure_guild(
                    session,
                    detection.event.guild_id,
                    name=str(self.get_guild(detection.event.guild_id).name)
                    if self.get_guild(detection.event.guild_id)
                    else "Unknown Guild",
                    owner_id=self.get_guild(detection.event.guild_id).owner_id
                    if self.get_guild(detection.event.guild_id)
                    else 0,
                )
                await self.security_persistence.record(session, detection)
        except Exception:
            logger.exception(
                "Security persistence failed; detection remains in-memory: guild=%s fingerprint=%s",
                detection.event.guild_id,
                detection.event.fingerprint,
            )

    async def _process_security_event(self, event: SecurityEvent, guild: discord.Guild) -> None:
        """Enrich a Gateway event with audit identity, score it, then persist it."""
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
                event.guild_id,
                match.audit_log_id,
                match.actor_id,
                match.action,
                event.target_id,
            )

        detection = self.event_correlator.process(event)
        if detection.velocity_count == 0:
            logger.debug("Duplicate security event suppressed: %s", event.fingerprint)
            return

        await self._persist_detection(detection)

        logger.info(
            "Security event: guild=%s type=%s actor=%s target=%s risk=%d velocity=%d/%ss reason=%s",
            event.guild_id,
            event.event_type.value,
            event.actor_id,
            event.target_id,
            detection.signal.score,
            detection.velocity_count,
            detection.velocity_window_seconds,
            detection.signal.reason,
        )

        if detection.signal.score >= 80:
            logger.critical(
                "CRITICAL security pattern detected: guild=%s actor=%s type=%s target=%s risk=%d",
                event.guild_id,
                event.actor_id,
                event.event_type.value,
                event.target_id,
                detection.signal.score,
            )
        elif detection.signal.score >= 60:
            logger.warning(
                "HIGH security pattern detected: guild=%s actor=%s type=%s target=%s risk=%d",
                event.guild_id,
                event.actor_id,
                event.event_type.value,
                event.target_id,
                detection.signal.score,
            )

    def _log_permission_findings(self, guild: discord.Guild) -> None:
        for finding in self.permission_audit.audit_guild(guild):
            logger.warning(
                "Privileged role detected: guild=%s role=%s name=%r severity=%s permissions=%s owner_role=%s",
                guild.id,
                finding.role_id,
                finding.role_name,
                finding.severity,
                ",".join(finding.permissions),
                finding.is_owner_role,
            )

    async def start_bot(self) -> None:
        if not settings.discord_token:
            raise RuntimeError("DISCORD_TOKEN is not configured")
        await self.start(settings.discord_token)
