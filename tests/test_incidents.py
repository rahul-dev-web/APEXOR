from app.core.constants import SecurityEventType
from app.security.events import Detection, SecurityEvent
from app.security.incidents import IncidentAggregator
from app.security.risk import RiskSignal


def _detection(
    *,
    guild_id: int = 1,
    actor_id: int | None = 10,
    event_type: SecurityEventType = SecurityEventType.CHANNEL_DELETE,
    score: int = 70,
    timestamp: float = 100.0,
    protected: bool = False,
) -> Detection:
    event = SecurityEvent(
        guild_id=guild_id,
        actor_id=actor_id,
        event_type=event_type,
        target_id=500,
        protected_target=protected,
        timestamp=timestamp,
    )
    return Detection(
        event=event,
        signal=RiskSignal(score=score, reason="test"),
        velocity_count=1,
        velocity_window_seconds=10,
    )


def test_low_risk_events_do_not_open_incidents() -> None:
    aggregator = IncidentAggregator()
    assert aggregator.ingest(_detection(score=59), now=100.0) is None


def test_related_destructive_events_escalate_incident() -> None:
    aggregator = IncidentAggregator(window_seconds=15)

    first = aggregator.ingest(_detection(score=70, timestamp=100.0), now=100.0)
    second = aggregator.ingest(_detection(score=80, timestamp=101.0), now=101.0)

    assert first is not None
    assert second is not None
    assert second.incident_type == "DESTRUCTIVE_RESOURCE_ACTIVITY"
    assert second.event_count == 2
    assert second.risk_score == 85
    assert second.severity == "CRITICAL"


def test_protected_target_adds_incident_weight() -> None:
    aggregator = IncidentAggregator()
    incident = aggregator.ingest(
        _detection(score=80, protected=True),
        now=100.0,
    )

    assert incident is not None
    assert incident.risk_score == 100
    assert incident.severity == "EMERGENCY"


def test_actor_and_type_are_isolated() -> None:
    aggregator = IncidentAggregator()
    aggregator.ingest(_detection(actor_id=10, timestamp=100.0), now=100.0)
    other = aggregator.ingest(_detection(actor_id=20, timestamp=101.0), now=101.0)

    assert other is not None
    assert other.event_count == 1
    assert other.actor_id == 20


def test_expired_window_starts_a_fresh_bucket() -> None:
    aggregator = IncidentAggregator(window_seconds=15)
    aggregator.ingest(_detection(timestamp=100.0), now=100.0)
    fresh = aggregator.ingest(_detection(timestamp=120.0), now=120.0)

    assert fresh is not None
    assert fresh.event_count == 1
