from types import SimpleNamespace

from app.core.constants import ProtectionState, SecurityEventType
from app.security.decision_runtime import resolve_decision
from app.security.events import Detection, SecurityEvent
from app.security.risk import RiskSignal


def _detection(score: int, event_type: SecurityEventType, *, protected: bool = False) -> Detection:
    return Detection(
        event=SecurityEvent(
            guild_id=1,
            actor_id=10,
            target_id=20,
            event_type=event_type,
            protected_target=protected,
        ),
        signal=RiskSignal(score=score, reason="test"),
        velocity_count=1,
        velocity_window_seconds=10,
    )


def test_runtime_uses_guild_thresholds_and_flags() -> None:
    config = SimpleNamespace(
        risk_threshold_high=50,
        risk_threshold_critical=75,
        risk_threshold_emergency=90,
        lockdown_enabled=True,
        recovery_enabled=True,
    )

    runtime = resolve_decision(
        _detection(75, SecurityEventType.CHANNEL_DELETE, protected=True),
        config,
    )

    assert runtime.state == ProtectionState.HIGH_RISK
    assert runtime.should_lockdown is True
    assert runtime.should_analyze_with_ai is True
    assert runtime.should_recover is True


def test_runtime_without_config_uses_safe_defaults() -> None:
    runtime = resolve_decision(
        _detection(95, SecurityEventType.ROLE_UPDATE),
        None,
    )

    assert runtime.state == ProtectionState.LOCKDOWN
    assert runtime.should_lockdown is True
    assert runtime.should_analyze_with_ai is True
