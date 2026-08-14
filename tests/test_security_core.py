from app.core.constants import SecurityEventType
from app.security.events import EventCorrelator, SecurityEvent
from app.security.risk import combine_signals


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
    assert detections[2].signal.score == 55
    assert detections[4].velocity_count == 5
    assert detections[4].signal.score == 85


def test_duplicate_event_is_not_counted_twice() -> None:
    correlator = EventCorrelator(window_seconds=10)
    event = SecurityEvent(
        guild_id=1,
        actor_id=42,
        target_id=99,
        event_type=SecurityEventType.ROLE_DELETE,
        event_id="same-event",
    )

    first = correlator.process(event, now=1.0)
    duplicate = correlator.process(event, now=1.1)

    assert first.velocity_count == 1
    assert duplicate.velocity_count == 0
