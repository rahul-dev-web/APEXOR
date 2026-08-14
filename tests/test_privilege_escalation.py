from app.core.constants import SecurityEventType
from app.security.events import EventCorrelator, SecurityEvent
from app.security.risk import score_event


def test_administrator_grant_is_emergency_risk() -> None:
    signal = score_event(SecurityEventType.ROLE_UPDATE, permission_added=("administrator",))
    assert signal.score == 95
    assert "permission_grant=administrator" in signal.reason


def test_manage_channels_grant_is_high_risk() -> None:
    signal = score_event(SecurityEventType.ROLE_UPDATE, permission_added=("manage_channels",))
    assert signal.score == 85


def test_permission_removal_does_not_raise_escalation_score() -> None:
    signal = score_event(SecurityEventType.ROLE_UPDATE, permission_added=())
    assert signal.score == 20


def test_correlator_preserves_permission_escalation_metadata() -> None:
    correlator = EventCorrelator(window_seconds=10.0)
    event = SecurityEvent(
        guild_id=1,
        event_type=SecurityEventType.ROLE_UPDATE,
        target_id=10,
        actor_id=20,
        permission_added=("administrator",),
    )
    detection = correlator.process(event, now=100.0)
    assert detection.velocity_count == 1
    assert detection.signal.score == 95
    assert detection.event.permission_added == ("administrator",)
