from app.core.constants import SecurityEventType
from app.security.events import EventCorrelator, SecurityEvent
from app.security.risk import score_event


def test_protected_channel_delete_is_critical_baseline():
    signal = score_event(SecurityEventType.CHANNEL_DELETE, protected_target=True)
    assert signal.score == 65
    assert "protected_target" in signal.reason


def test_channel_delete_velocity_reaches_critical():
    correlator = EventCorrelator(window_seconds=10)
    detections = [
        correlator.process(
            SecurityEvent(
                guild_id=1,
                actor_id=42,
                target_id=index,
                event_type=SecurityEventType.CHANNEL_DELETE,
                event_id=f"evt-{index}",
            ),
            now=float(index),
        )
        for index in range(1, 6)
    ]

    assert detections[-1].velocity_count == 5
    assert detections[-1].signal.score == 65


def test_duplicate_event_is_suppressed():
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
