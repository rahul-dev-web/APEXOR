from datetime import datetime, timedelta, timezone

from app.core.constants import SecurityEventType
from app.security.velocity import VelocityTracker


def test_destructive_velocity_escalates_within_window() -> None:
    tracker = VelocityTracker(max_window_seconds=10)
    start = datetime(2026, 8, 15, tzinfo=timezone.utc)

    first = tracker.record(1, 10, SecurityEventType.CHANNEL_DELETE, occurred_at=start)
    second = tracker.record(1, 10, SecurityEventType.CHANNEL_DELETE, occurred_at=start + timedelta(seconds=1))
    third = tracker.record(1, 10, SecurityEventType.CHANNEL_DELETE, occurred_at=start + timedelta(seconds=2))
    fourth = tracker.record(1, 10, SecurityEventType.CHANNEL_DELETE, occurred_at=start + timedelta(seconds=4))
    fifth = tracker.record(1, 10, SecurityEventType.CHANNEL_DELETE, occurred_at=start + timedelta(seconds=9))

    assert first.count == 1
    assert first.score_bonus == 0
    assert second.count == 2
    assert third.score_bonus == 25
    assert fourth.count == 4
    assert fourth.score_bonus == 25
    assert fifth.count == 5
    assert fifth.score_bonus == 50


def test_old_events_expire_from_sliding_window() -> None:
    tracker = VelocityTracker(max_window_seconds=10)
    start = datetime(2026, 8, 15, tzinfo=timezone.utc)

    tracker.record(1, 10, SecurityEventType.CHANNEL_DELETE, occurred_at=start)
    tracker.record(1, 10, SecurityEventType.CHANNEL_DELETE, occurred_at=start + timedelta(seconds=1))
    current = tracker.record(
        1,
        10,
        SecurityEventType.CHANNEL_DELETE,
        occurred_at=start + timedelta(seconds=12),
    )

    assert current.count == 1
    assert current.score_bonus == 0


def test_actor_and_guild_clear_are_isolated() -> None:
    tracker = VelocityTracker()
    now = datetime(2026, 8, 15, tzinfo=timezone.utc)

    tracker.record(1, 10, SecurityEventType.CHANNEL_DELETE, occurred_at=now)
    tracker.record(1, 20, SecurityEventType.CHANNEL_DELETE, occurred_at=now)
    tracker.record(2, 10, SecurityEventType.CHANNEL_DELETE, occurred_at=now)

    tracker.clear_actor(1, 10)
    remaining = tracker.record(1, 10, SecurityEventType.CHANNEL_DELETE, occurred_at=now + timedelta(seconds=1))
    assert remaining.count == 1

    tracker.clear_guild(1)
    remaining_other_guild = tracker.record(2, 10, SecurityEventType.CHANNEL_DELETE, occurred_at=now + timedelta(seconds=1))
    assert remaining_other_guild.count == 2
