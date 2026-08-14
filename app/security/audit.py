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


# Gateway events do not normally carry the actor. Audit Logs are therefore a
# second-stage identity source. Keep this mapping explicit and conservative:
# the correlator must never infer an actor from an unrelated audit action.
_ACTIONS: dict[SecurityEventType, tuple[discord.AuditLogAction, ...]] = {
    SecurityEventType.CHANNEL_CREATE: (discord.AuditLogAction.channel_create,),
    SecurityEventType.CHANNEL_UPDATE: (discord.AuditLogAction.channel_update,),
    SecurityEventType.CHANNEL_DELETE: (discord.AuditLogAction.channel_delete,),
    SecurityEventType.ROLE_CREATE: (discord.AuditLogAction.role_create,),
    SecurityEventType.ROLE_UPDATE: (discord.AuditLogAction.role_update,),
    SecurityEventType.ROLE_DELETE: (discord.AuditLogAction.role_delete,),
    SecurityEventType.GUILD_UPDATE: (discord.AuditLogAction.guild_update,),
}

# Some event families have several Discord audit actions. They are resolved
# dynamically so APXOR remains compatible with discord.py versions that expose
# a subset of newer audit action enum members.
_OPTIONAL_ACTION_NAMES: dict[SecurityEventType, tuple[str, ...]] = {
    SecurityEventType.MEMBER_UPDATE: ("member_update", "member_role_update"),
    SecurityEventType.MEMBER_REMOVE: ("member_kick", "member_ban_add", "member_ban_remove"),
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


class AuditLogCorrelator:
    """Resolve Gateway events to Discord audit-log actors when possible.

    Correlation is deliberately best-effort. A missing permission, a transient
    API failure, or an eventually-consistent audit log must never disable the
    deterministic Gateway detector. When multiple entries match, the newest
    matching entry is selected because Discord audit logs are returned newest
    first.
    """

    def __init__(self, *, limit: int = 10) -> None:
        self.limit = max(1, min(limit, 100))

    async def correlate(self, guild: discord.Guild, event: SecurityEvent) -> AuditMatch | None:
        actions = _actions_for(event.event_type)
        if not actions:
            return None

        # One request per action type would multiply REST traffic during a nuke.
        # Fetch a bounded recent window once, then match against the known event
        # target/action locally.
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
