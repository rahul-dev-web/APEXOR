from types import SimpleNamespace

import discord

from app.core.constants import SecurityEventType
from app.security.events import EventCorrelator, SecurityEvent
from app.security.permissions.audit import PermissionAudit
from app.security.risk import combine_signals, score_event


def _role(role_id: int, name: str, permissions: discord.Permissions) -> SimpleNamespace:
    return SimpleNamespace(id=role_id, name=name, permissions=permissions)


def test_administrator_is_emergency_for_non_owner_role() -> None:
    policy_audit = PermissionAudit()
    permissions = discord.Permissions.none()
    permissions.administrator = True

    finding = policy_audit.audit_role(
        _role(123, "Compromised Moderator", permissions),
        owner_role=False,
    )

    assert finding is not None
    assert finding.severity == "EMERGENCY"
    assert finding.permissions == ("administrator",)


def test_owner_role_is_not_marked_as_emergency() -> None:
    policy_audit = PermissionAudit()
    permissions = discord.Permissions(administrator=True)

    finding = policy_audit.audit_role(
        _role(456, "Owner", permissions),
        owner_role=True,
    )

    assert finding is not None
    assert finding.severity == "INFO"


def test_protected_channel_delete_is_critical_weight() -> None:
    signal = score_event(SecurityEventType.CHANNEL_DELETE, protected_target=True)

    assert signal.score == 65
    assert "protected_target" in signal.reason


def test_risk_score_is_capped_at_100() -> None:
    signals = [
        score_event(SecurityEventType.CHANNEL_DELETE, protected_target=True),
        score_event(SecurityEventType.ROLE_DELETE, protected_target=True),
        score_event(SecurityEventType.GUILD_UPDATE, protected_target=True),
    ]

    assert combine_signals(signals) == 100


def test_channel_delete_velocity_escalates_deterministically() -> None:
    correlator = EventCorrelator(window_seconds=10)
    detections = [
        correlator.process(
            SecurityEvent(
                guild_id=1,
                actor_id=42,
                target_id=index,
                event_type=SecurityEventType.CHANNEL_DELETE,
            ),
            now=float(index),
        )
        for index in range(1, 6)
    ]

    assert detections[0].velocity_count == 1
    assert detections[2].velocity_count == 3
    assert detections[2].signal.score == 45
    assert detections[4].velocity_count == 5
    assert detections[4].signal.score == 65


def test_duplicate_event_is_not_counted_twice() -> None:
    correlator = EventCorrelator(window_seconds=10)
    event = SecurityEvent(
        guild_id=1,
        actor_id=42,
        target_id=99,
        event_type=SecurityEventType.CHANNEL_DELETE,
        timestamp=10.0,
    )

    first = correlator.process(event, now=10.0)
    duplicate = correlator.process(event, now=10.0)

    assert first.velocity_count == 1
    assert duplicate.velocity_count == 0
