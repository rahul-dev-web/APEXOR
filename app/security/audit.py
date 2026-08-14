from __future__ import annotations

from dataclasses import dataclass

import discord

from app.core.constants import SecurityEventType
from app.security.events import SecurityEvent


@dataclass(frozen=True, slots=True)
class AuditMatch:
    audit_log_id: int
    actor_id: int | None
    action: str


_ACTIONS: dict[SecurityEventType, discord.AuditLogAction] = {
    SecurityEventType.CHANNEL_CREATE: discord.AuditLogAction.channel_create,
    SecurityEventType.CHANNEL_UPDATE: discord.AuditLogAction.channel_update,
    SecurityEventType.CHANNEL_DELETE: discord.AuditLogAction.channel_delete,
    SecurityEventType.ROLE_CREATE: discord.AuditLogAction.role_create,
    SecurityEventType.ROLE_UPDATE: discord.AuditLogAction.role_update,
    SecurityEventType.ROLE_DELETE: discord.AuditLogAction.role_delete,
    SecurityEventType.GUILD_UPDATE: discord.AuditLogAction.guild_update,
}


class AuditLogCorrelator:
    """Resolve Gateway events to the Discord audit-log actor when possible.

    Gateway lifecycle events identify the affected resource but generally do not
    identify the human/bot actor. The audit log is therefore a second-stage
    identity source. This service is read-only and never mutates Discord state.
    """

    def __init__(self, *, limit: int = 10) -> None:
        self.limit = limit

    async def correlate(self, guild: discord.Guild, event: SecurityEvent) -> AuditMatch | None:
        action = _ACTIONS.get(event.event_type)
        if action is None:
            return None

        try:
            async for entry in guild.audit_logs(limit=self.limit, action=action):
                if not self._target_matches(entry, event):
                    continue
                return AuditMatch(
                    audit_log_id=entry.id,
                    actor_id=entry.user.id if entry.user is not None else None,
                    action=str(entry.action),
                )
        except (discord.Forbidden, discord.HTTPException):
            # Missing VIEW_AUDIT_LOG or a transient Discord API failure must not
            # disable the deterministic Gateway detector.
            return None

        return None

    @staticmethod
    def _target_matches(entry: discord.AuditLogEntry, event: SecurityEvent) -> bool:
        if event.event_type is SecurityEventType.GUILD_UPDATE:
            return True
        if event.target_id is None:
            return False
        target = entry.target
        target_id = getattr(target, "id", target if isinstance(target, int) else None)
        return target_id == event.target_id
