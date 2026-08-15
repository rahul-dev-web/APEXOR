from app.core.constants import ProtectionState, SecurityEventType
from app.security.decision_runtime import resolve_decision
from app.security.events import EventCorrelator, SecurityEvent
from app.security.risk import score_event


def _event(
    event_type: SecurityEventType,
    *,
    actor_id: int = 42,
    target_id: int = 100,
    event_id: str | None = None,
    audit_log_id: int | None = None,
    protected: bool = False,
    permission_added: tuple[str, ...] = (),
    timestamp: float = 100.0,
) -> SecurityEvent:
    return SecurityEvent(
        guild_id=1,
        actor_id=actor_id,
        target_id=target_id,
        event_type=event_type,
        event_id=event_id,
        audit_log_id=audit_log_id,
        protected_target=protected,
        permission_added=permission_added,
        timestamp=timestamp,
    )


def test_mass_channel_delete_reaches_lockdown_range() -> None:
    correlator = EventCorrelator(window_seconds=10)

    detections = [
        correlator.process(
            _event(
                SecurityEventType.CHANNEL_DELETE,
                target_id=index,
                event_id=f"delete-{index}",
            ),
            now=100.0 + index * 0.1,
        )
        for index in range(20)
    ]

    assert detections[-1].velocity_count == 20
    assert detections[-1].signal.score == 85

    runtime = resolve_decision(detections[-1], None)
    assert runtime.state == ProtectionState.HIGH_RISK
    assert runtime.should_lockdown is True
    assert runtime.should_recover is True


def test_protected_channel_delete_escalates_immediately() -> None:
    detection = EventCorrelator().process(
        _event(
            SecurityEventType.CHANNEL_DELETE,
            protected=True,
            event_id="protected-delete",
        ),
        now=100.0,
    )

    assert detection.signal.score == 65
    assert detection.event.protected_target is True


def test_administrator_permission_grant_is_critical() -> None:
    signal = score_event(
        SecurityEventType.ROLE_UPDATE,
        permission_added=("administrator",),
    )

    assert signal.score == 95
    assert "permission_grant=administrator" in signal.reason

    detection = EventCorrelator().process(
        _event(
            SecurityEventType.ROLE_UPDATE,
            event_id="admin-grant",
            permission_added=("administrator",),
        ),
        now=100.0,
    )
    runtime = resolve_decision(detection, None)
    assert runtime.state == ProtectionState.LOCKDOWN
    assert runtime.should_lockdown is True


def test_duplicate_gateway_event_is_idempotent() -> None:
    correlator = EventCorrelator(window_seconds=10)
    event = _event(
        SecurityEventType.CHANNEL_DELETE,
        event_id="same-event",
    )

    first = correlator.process(event, now=100.0)
    duplicate = correlator.process(event, now=100.1)

    assert first.velocity_count == 1
    assert duplicate.velocity_count == 0
    assert duplicate.signal.score == first.signal.score


def test_audit_log_identity_deduplicates_even_when_gateway_event_id_differs() -> None:
    correlator = EventCorrelator(window_seconds=10)
    first = correlator.process(
        _event(
            SecurityEventType.ROLE_DELETE,
            audit_log_id=9001,
            event_id="gateway-1",
        ),
        now=100.0,
    )
    duplicate = correlator.process(
        _event(
            SecurityEventType.ROLE_DELETE,
            audit_log_id=9001,
            event_id="gateway-2",
        ),
        now=100.2,
    )

    assert first.velocity_count == 1
    assert duplicate.velocity_count == 0


def test_mixed_destructive_attack_escalates_faster_than_single_event_type() -> None:
    correlator = EventCorrelator(window_seconds=10)
    events = [
        (SecurityEventType.CHANNEL_DELETE, "channel"),
        (SecurityEventType.ROLE_DELETE, "role"),
        (SecurityEventType.BAN_ADD, "ban"),
        (SecurityEventType.WEBHOOK_UPDATE, "webhook"),
        (SecurityEventType.INTEGRATION_UPDATE, "integration"),
    ]

    last = None
    for index, (event_type, name) in enumerate(events):
        last = correlator.process(
            _event(event_type, event_id=name),
            now=100.0 + index * 0.2,
        )

    assert last is not None
    assert last.velocity_count == 1
    assert last.signal.score >= 50
    assert "destructive_window_5" in last.signal.reason


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

    # The newest old event is at t=102; t=113 is outside the 10-second window.
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
            now=100.0 + index * 0.001,
        )

    assert last is not None
    assert last.velocity_count == 256
    assert last.signal.score <= 100
