from datetime import datetime, timedelta, timezone

from app.core.constants import SecurityEventType
from app.security.velocity import VelocityTracker


def test_mixed_destructive_actions_escalate_actor_risk() -> None:
    tracker = VelocityTracker(max_window_seconds=10)
    start = datetime(2026, 8, 15, tzinfo=timezone.utc)

    tracker.record(1, 10, SecurityEventType.CHANNEL_DELETE, occurred_at=start)
    tracker.record(1, 10, SecurityEventType.ROLE_DELETE, occurred_at=start + timedelta(seconds=1))
    signal = tracker.record(1, 10, SecurityEventType.BAN_ADD, occurred_at=start + timedelta(seconds=2))

    assert signal.score_bonus >= 10
    assert "mixed_destructive=3/3" in signal.reason


def test_mixed_bonus_does_not_cross_window_boundary() -> None:
    tracker = VelocityTracker(max_window_seconds=10)
    start = datetime(2026, 8, 15, tzinfo=timezone.utc)

    tracker.record(1, 10, SecurityEventType.CHANNEL_DELETE, occurred_at=start)
    tracker.record(1, 10, SecurityEventType.ROLE_DELETE, occurred_at=start + timedelta(seconds=1))
    signal = tracker.record(
        1,
        10,
        SecurityEventType.BAN_ADD,
        occurred_at=start + timedelta(seconds=12),
    )

    assert signal.score_bonus == 0
    assert "mixed_destructive" not in signal.reason


def test_clear_actor_removes_mixed_history() -> None:
    tracker = VelocityTracker(max_window_seconds=10)
    start = datetime(2026, 8, 15, tzinfo=timezone.utc)

    tracker.record(1, 10, SecurityEventType.CHANNEL_DELETE, occurred_at=start)
    tracker.record(1, 10, SecurityEventType.ROLE_DELETE, occurred_at=start + timedelta(seconds=1))
    tracker.clear_actor(1, 10)

    signal = tracker.record(1, 10, SecurityEventType.BAN_ADD, occurred_at=start + timedelta(seconds=2))
    assert signal.score_bonus == 0
    assert "mixed_destructive" not in signal.reason
