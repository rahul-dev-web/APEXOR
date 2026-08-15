from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import discord

from app.core.constants import SecurityEventType
from app.security.events import SecurityEvent


@dataclass(frozen=True, slots=True)
class AuditMatch:
    audit_log_id: int
    actor_id: int | None
    action: str


# discord.py 2.x exposes moderation audit actions as ``ban`` and ``unban``.
# Keep the mapping explicit so importing this module cannot fail on supported
# discord.py releases because of legacy/non-existent action names.
_ACTIONS: dict[SecurityEventType, tuple[discord.AuditLogAction, ...]] = {
    SecurityEventType.CHANNEL_CREATE: (discord.AuditLogAction.channel_create,),
    SecurityEventType.CHANNEL_UPDATE: (discord.AuditLogAction.channel_update,),
    SecurityEventType.CHANNEL_DELETE: (discord.AuditLogAction.channel_delete,),
    SecurityEventType.ROLE_CREATE: (discord.AuditLogAction.role_create,),
    SecurityEventType.ROLE_UPDATE: (discord.AuditLogAction.role_update,),
    SecurityEventType.ROLE_DELETE: (discord.AuditLogAction.role_delete,),
    SecurityEventType.GUILD_UPDATE: (discord.AuditLogAction.guild_update,),
    SecurityEventType.KICK: (discord.AuditLogAction.kick,),
    SecurityEventType.BAN_ADD: (discord.AuditLogAction.ban,),
    SecurityEventType.BAN_REMOVE: (discord.AuditLogAction.unban,),
}

_OPTIONAL_ACTION_NAMES: dict[SecurityEventType, tuple[str, ...]] = {
    SecurityEventType.MEMBER_UPDATE: ("member_update", "member_role_update"),
    SecurityEventType.WEBHOOK_UPDATE: ("webhook_create", "webhook_update", "webhook_delete"),
    SecurityEventType.INTEGRATION_UPDATE: ("integration_create", "integration_update", "integration_delete"),
}

# REST audit-log queries are eventually consistent. A target match alone is
# not enough because an older action against the same target can otherwise be
# incorrectly attributed to a new Gateway/resource event. Keep the fallback
# correlation window deliberately short; the real-time audit Gateway event
# remains the preferred source when available.
AUDIT_CORRELATION_MAX_AGE_SECONDS = 30.0


def _actions_for(event_type: SecurityEventType) -> tuple[discord.AuditLogAction, ...]:
    actions = list(_ACTIONS.get(event_type, ()))
    for name in _OPTIONAL_ACTION_NAMES.get(event_type, ()):
        action = getattr(discord.AuditLogAction, name, None)
        if action is not None and action not in actions:
            actions.append(action)
    return tuple(actions)


def event_type_for_audit_action(action: discord.AuditLogAction) -> SecurityEventType | None:
    """Translate a Discord audit action into APEXOR's normalized event type."""
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
    """Resolve Gateway/resource events to recent Discord audit-log actors."""

    def __init__(self, *, limit: int = 10, max_age_seconds: float = AUDIT_CORRELATION_MAX_AGE_SECONDS) -> None:
        self.limit = max(1, min(limit, 100))
        self.max_age_seconds = max(0.0, max_age_seconds)

    async def correlate(self, guild: discord.Guild, event: SecurityEvent) -> AuditMatch | None:
        actions = _actions_for(event.event_type)
        if not actions:
            return None
        try:
            async for entry in guild.audit_logs(limit=self.limit):
                if entry.action not in actions:
                    continue
                if not self._is_recent(entry):
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

    def _is_recent(self, entry: discord.AuditLogEntry) -> bool:
        """Reject stale REST entries when Discord exposes their creation time.

        Test doubles and partial library objects may not expose ``created_at``;
        in that case correlation retains the previous behavior.
        """
        created_at = getattr(entry, "created_at", None)
        if created_at is None or not isinstance(created_at, datetime):
            return True
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - created_at).total_seconds()
        return -2.0 <= age <= self.max_age_seconds

    @staticmethod
    def _target_matches(entry: discord.AuditLogEntry, event: SecurityEvent) -> bool:
        if event.event_type is SecurityEventType.GUILD_UPDATE:
            return True
        if event.target_id is None:
            return False
        target = entry.target
        target_id = getattr(target, "id", target if isinstance(target, int) else None)
        return target_id == event.target_id
