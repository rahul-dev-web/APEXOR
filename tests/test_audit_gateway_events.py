from types import SimpleNamespace

import discord

from app.core.constants import SecurityEventType
from app.security.audit import event_from_audit_entry, event_type_for_audit_action


def test_known_audit_action_maps_to_security_event() -> None:
    assert event_type_for_audit_action(discord.AuditLogAction.channel_delete) is SecurityEventType.CHANNEL_DELETE
    assert event_type_for_audit_action(discord.AuditLogAction.role_update) is SecurityEventType.ROLE_UPDATE
    assert event_type_for_audit_action(discord.AuditLogAction.ban_add) is SecurityEventType.BAN_ADD
    assert event_type_for_audit_action(discord.AuditLogAction.kick) is SecurityEventType.KICK


def test_audit_entry_normalizes_actor_target_and_audit_id() -> None:
    guild = SimpleNamespace(id=123)
    actor = SimpleNamespace(id=456)
    target = SimpleNamespace(id=789)
    entry = SimpleNamespace(
        id=987,
        action=discord.AuditLogAction.channel_delete,
        user=actor,
        target=target,
    )

    event = event_from_audit_entry(guild, entry)

    assert event is not None
    assert event.guild_id == 123
    assert event.event_type is SecurityEventType.CHANNEL_DELETE
    assert event.actor_id == 456
    assert event.target_id == 789
    assert event.audit_log_id == 987
    assert event.fingerprint == "audit:123:987"


def test_unknown_audit_action_is_ignored() -> None:
    guild = SimpleNamespace(id=123)
    entry = SimpleNamespace(id=987, action=object(), user=None, target=None)

    assert event_from_audit_entry(guild, entry) is None
