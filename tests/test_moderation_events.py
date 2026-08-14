from app.core.constants import SecurityEventType
from app.security.events import EventCorrelator, SecurityEvent


def test_mixed_ban_and_channel_delete_activity_escalates() -> None:
    correlator = EventCorrelator(window_seconds=10.0)

    first = correlator.process(
        SecurityEvent(guild_id=1, actor_id=10, event_type=SecurityEventType.BAN_ADD, target_id=100),
        now=100.0,
    )
    second = correlator.process(
        SecurityEvent(guild_id=1, actor_id=10, event_type=SecurityEventType.CHANNEL_DELETE, target_id=200),
        now=101.0,
    )
    third = correlator.process(
        SecurityEvent(guild_id=1, actor_id=10, event_type=SecurityEventType.ROLE_DELETE, target_id=300),
        now=102.0,
    )

    assert first.signal.score == 30
    assert second.signal.score >= 35
    assert third.signal.score >= 50
    assert "destructive_window_3" in third.signal.reason


def test_ban_velocity_escalates() -> None:
    correlator = EventCorrelator(window_seconds=10.0)
    for index in range(4):
        detection = correlator.process(
            SecurityEvent(
                guild_id=1,
                actor_id=10,
                event_type=SecurityEventType.BAN_ADD,
                target_id=100 + index,
            ),
            now=100.0 + index,
        )

    assert detection.velocity_count == 4
    assert detection.signal.score >= 40
