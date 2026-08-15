from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import discord
import pytest

from app.core.constants import SecurityEventType
from app.security.audit import AuditLogCorrelator
from app.security.events import SecurityEvent


class AsyncEntries:
    def __init__(self, entries):
        self.entries = entries

    def __aiter__(self):
        self._iterator = iter(self.entries)
        return self

    async def __anext__(self):
        try:
            return next(self._iterator)
        except StopIteration:
            raise StopAsyncIteration


@pytest.mark.asyncio
async def test_correlates_channel_delete_to_actor():
    actor = SimpleNamespace(id=123)
    target = SimpleNamespace(id=456)
    entry = SimpleNamespace(
        id=999,
        action=discord.AuditLogAction.channel_delete,
        target=target,
        user=actor,
    )
    guild = SimpleNamespace(audit_logs=lambda **kwargs: AsyncEntries([entry]))

    result = await AuditLogCorrelator().correlate(
        guild,
        SecurityEvent(
            guild_id=1,
            event_type=SecurityEventType.CHANNEL_DELETE,
            target_id=456,
        ),
    )

    assert result is not None
    assert result.audit_log_id == 999
    assert result.actor_id == 123
    assert result.action == str(discord.AuditLogAction.channel_delete)


@pytest.mark.asyncio
async def test_ignores_unrelated_audit_target():
    entry = SimpleNamespace(
        id=999,
        action=discord.AuditLogAction.channel_delete,
        target=SimpleNamespace(id=777),
        user=SimpleNamespace(id=123),
    )
    guild = SimpleNamespace(audit_logs=lambda **kwargs: AsyncEntries([entry]))

    result = await AuditLogCorrelator().correlate(
        guild,
        SecurityEvent(
            guild_id=1,
            event_type=SecurityEventType.CHANNEL_DELETE,
            target_id=456,
        ),
    )

    assert result is None


@pytest.mark.asyncio
async def test_ignores_stale_audit_entry_for_same_target():
    entry = SimpleNamespace(
        id=998,
        action=discord.AuditLogAction.channel_delete,
        target=SimpleNamespace(id=456),
        user=SimpleNamespace(id=321),
        created_at=datetime.now(timezone.utc) - timedelta(seconds=31),
    )
    guild = SimpleNamespace(audit_logs=lambda **kwargs: AsyncEntries([entry]))

    result = await AuditLogCorrelator().correlate(
        guild,
        SecurityEvent(
            guild_id=1,
            event_type=SecurityEventType.CHANNEL_DELETE,
            target_id=456,
        ),
    )

    assert result is None


@pytest.mark.asyncio
async def test_accepts_recent_audit_entry_with_timestamp():
    entry = SimpleNamespace(
        id=1000,
        action=discord.AuditLogAction.channel_delete,
        target=SimpleNamespace(id=456),
        user=SimpleNamespace(id=654),
        created_at=datetime.now(timezone.utc) - timedelta(seconds=2),
    )
    guild = SimpleNamespace(audit_logs=lambda **kwargs: AsyncEntries([entry]))

    result = await AuditLogCorrelator().correlate(
        guild,
        SecurityEvent(
            guild_id=1,
            event_type=SecurityEventType.CHANNEL_DELETE,
            target_id=456,
        ),
    )

    assert result is not None
    assert result.audit_log_id == 1000
    assert result.actor_id == 654


@pytest.mark.asyncio
async def test_audit_failure_is_non_fatal():
    def failing_audit_logs(**kwargs):
        raise discord.Forbidden.__new__(discord.Forbidden)

    guild = SimpleNamespace(audit_logs=failing_audit_logs)

    result = await AuditLogCorrelator().correlate(
        guild,
        SecurityEvent(
            guild_id=1,
            event_type=SecurityEventType.ROLE_DELETE,
            target_id=456,
        ),
    )

    assert result is None
