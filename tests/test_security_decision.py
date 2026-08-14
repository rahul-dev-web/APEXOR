from app.core.constants import ProtectionState, SecurityEventType
from app.security.decision import decide
from app.security.events import Detection, SecurityEvent
from app.security.risk import RiskSignal


def _detection(
    score: int,
    event_type: SecurityEventType,
    *,
    protected: bool = False,
) -> Detection:
    event = SecurityEvent(
        guild_id=1,
        actor_id=10,
        target_id=20,
        event_type=event_type,
        protected_target=protected,
    )
    return Detection(
        event=event,
        signal=RiskSignal(score=score, reason="test"),
        velocity_count=1,
        velocity_window_seconds=10,
    )


def test_normal_event_stays_protected() -> None:
    decision = decide(_detection(25, SecurityEventType.CHANNEL_DELETE))

    assert decision.state == ProtectionState.PROTECTED
    assert decision.severity is None
    assert decision.should_lockdown is False
    assert decision.should_analyze_with_ai is False
    assert decision.should_recover is False


def test_high_risk_event_requests_ai_but_not_lockdown() -> None:
    decision = decide(_detection(70, SecurityEventType.BAN_ADD))

    assert decision.state == ProtectionState.SUSPICIOUS
    assert decision.severity == "HIGH"
    assert decision.should_analyze_with_ai is True
    assert decision.should_lockdown is False
    assert decision.should_recover is False


def test_protected_channel_delete_locks_down_at_high_threshold() -> None:
    decision = decide(
        _detection(60, SecurityEventType.CHANNEL_DELETE, protected=True)
    )

    assert decision.should_lockdown is True
    assert decision.should_recover is True
    assert decision.recovery_resource_type == "CHANNEL"
    assert decision.recovery_priority == 10


def test_emergency_privilege_event_enters_lockdown() -> None:
    decision = decide(_detection(95, SecurityEventType.ROLE_UPDATE))

    assert decision.state == ProtectionState.LOCKDOWN
    assert decision.severity == "EMERGENCY"
    assert decision.should_lockdown is True
    assert decision.should_analyze_with_ai is True


def test_policy_flags_can_disable_mutations_without_disabling_analysis() -> None:
    decision = decide(
        _detection(95, SecurityEventType.CHANNEL_DELETE),
        lockdown_enabled=False,
        recovery_enabled=False,
    )

    assert decision.should_lockdown is False
    assert decision.should_recover is False
    assert decision.should_analyze_with_ai is True
