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


_ACTIONS: dict[SecurityEventType, tuple[discord.AuditLogAction, ...]] = {
    SecurityEventType.CHANNEL_CREATE: (discord.AuditLogAction.channel_create,),
    SecurityEventType.CHANNEL_UPDATE: (discord.AuditLogAction.channel_update,),
    SecurityEventType.CHANNEL_DELETE: (discord.AuditLogAction.channel_delete,),
    SecurityEventType.ROLE_CREATE: (discord.AuditLogAction.role_create,),
    SecurityEventType.ROLE_UPDATE: (discord.AuditLogAction.role_update,),
    SecurityEventType.ROLE_DELETE: (discord.AuditLogAction.role_delete,),
    SecurityEventType.GUILD_UPDATE: (discord.AuditLogAction.guild_update,),
    SecurityEventType.KICK: (discord.AuditLogAction.kick,),
    SecurityEventType.BAN_ADD: (discord.AuditLogAction.ban_add,),
    SecurityEventType.BAN_REMOVE: (discord.AuditLogAction.ban_remove,),
}

_OPTIONAL_ACTION_NAMES: dict[SecurityEventType, tuple[str, ...]] = {
    SecurityEventType.MEMBER_UPDATE: ("member_update", "member_role_update"),
    SecurityEventType.WEBHOOK_UPDATE: ("webhook_create", "webhook_update", "webhook_delete"),
    SecurityEventType.INTEGRATION_UPDATE: ("integration_create", "integration_update", "integration_delete"),
}


def _actions_for(event_type: SecurityEventType) -> tuple[discord.AuditLogAction, ...]:
    actions = list(_ACTIONS.get(event_type, ()))
    for name in _OPTIONAL_ACTION_NAMES.get(event_type, ()):
        action = getattr(discord.AuditLogAction, name, None)
        if action is not None and action not in actions:
            actions.append(action)
    return tuple(actions)


def event_type_for_audit_action(action: discord.AuditLogAction) -> SecurityEventType | None:
    """Translate a Discord audit action into APXOR's normalized event type."""
    for event_type in SecurityEventType:
        if action in _actions_for(event_type):
            return event_type
    return None


def event_from_audit_entry(guild: discord.Guild, entry: discord.AuditLogEntry) -> SecurityEvent | None:
    """Build a normalized security event directly from a Gateway audit entry."""
    event_type = event_type_for_audit_action(entry.action)
    if event_type is None:
        return None

    target = entry.target
    target_id = getattr(target, "id", target if isinstance(target, int) else None)
    actor_id = entry.user.id if entry.user is not None else None
    return SecurityEvent(
        guild_id=guild.id,
        event_type=event_type,
        target_id=target_id,
        actor_id=actor_id,
        audit_log_id=entry.id,
    )


class AuditLogCorrelator:
    """Resolve Gateway events to Discord audit-log actors when possible."""

    def __init__(self, *, limit: int = 10) -> None:
        self.limit = max(1, min(limit, 100))

    async def correlate(self, guild: discord.Guild, event: SecurityEvent) -> AuditMatch | None:
        actions = _actions_for(event.event_type)
        if not actions:
            return None
        try:
            async for entry in guild.audit_logs(limit=self.limit):
                if entry.action not in actions:
                    continue
                if not self._target_matches(entry, event):
                    continue
                return AuditMatch(
                    audit_log_id=entry.id,
                    actor_id=entry.user.id if entry.user is not None else None,
                    action=str(entry.action),
                )
        except (discord.Forbidden, discord.HTTPException):
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
