from app.core.constants import SecurityEventType
from app.security.events import EventCorrelator, SecurityEvent


def _event(event_type: SecurityEventType, *, target_id: int, event_id: str) -> SecurityEvent:
    return SecurityEvent(
        guild_id=1,
        actor_id=42,
        event_type=event_type,
        target_id=target_id,
        event_id=event_id,
    )


def test_velocity_window_expires_old_events() -> None:
    correlator = EventCorrelator(window_seconds=10)
    for index in range(3):
        correlator.process(
            _event(
                SecurityEventType.CHANNEL_DELETE,
                target_id=index,
                event_id=f"old-{index}",
            ),
            now=100.0 + index,
        )

    # The newest old event was at t=102; t=113 is more than one full
    # 10-second window later, so no old event should contribute to velocity.
    fresh = correlator.process(
        _event(
            SecurityEventType.CHANNEL_DELETE,
            target_id=999,
            event_id="fresh",
        ),
        now=113.0,
    )

    assert fresh.velocity_count == 1


def test_event_correlation_is_bounded_under_burst() -> None:
    correlator = EventCorrelator(window_seconds=10, max_events=256)
    last = None

    for index in range(500):
        last = correlator.process(
            _event(
                SecurityEventType.CHANNEL_DELETE,
                target_id=index,
                event_id=f"burst-{index}",
            ),
            now=100.0 + (index / 100.0),
        )

    assert last is not None
    assert last.velocity_count == 256
