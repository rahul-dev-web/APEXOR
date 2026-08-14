from app.core.constants import ProtectionState, SecurityEventType
from app.models.security import SecurityConfig
from app.security.events import Detection, SecurityEvent
from app.security.protection_runtime import ProtectionRuntime
from app.security.risk import RiskSignal


def detection(score: int, *, protected_target: bool = False) -> Detection:
    event = SecurityEvent(
        guild_id=1,
        event_type=SecurityEventType.CHANNEL_DELETE,
        protected_target=protected_target,
    )
    return Detection(
        event=event,
        signal=RiskSignal(score=score, reason="test"),
        velocity_count=1,
        velocity_window_seconds=10.0,
    )


def test_initialize_protection():
    runtime = ProtectionRuntime()
    result = runtime.initialize()

    assert result.current == ProtectionState.PROTECTED
    assert runtime.state == ProtectionState.PROTECTED


def test_critical_detection_enters_lockdown():
    runtime = ProtectionRuntime()
    runtime.initialize()

    result = runtime.evaluate(detection(95), None)

    assert result.state == ProtectionState.LOCKDOWN
    assert result.should_lockdown is True


def test_protected_resource_crosses_lockdown_boundary():
    runtime = ProtectionRuntime()
    runtime.initialize()

    result = runtime.evaluate(detection(60, protected_target=True), None)

    # Protected-resource containment can trigger below the normal emergency
    # state band. The persisted lifecycle must still reflect actual lockdown.
    assert result.decision.state == ProtectionState.SUSPICIOUS
    assert result.should_lockdown is True
    assert result.state == ProtectionState.LOCKDOWN


def test_runtime_respects_custom_risk_thresholds():
    runtime = ProtectionRuntime()
    runtime.initialize()
    config = SecurityConfig(
        guild_id=1,
        risk_threshold_high=50,
        risk_threshold_critical=70,
        risk_threshold_emergency=90,
        lockdown_enabled=True,
    )

    result = runtime.evaluate(detection(70), config)

    assert result.decision.state == ProtectionState.HIGH_RISK
    assert result.state == ProtectionState.LOCKDOWN


def test_low_risk_event_does_not_clear_lockdown():
    runtime = ProtectionRuntime()
    runtime.initialize()
    runtime.evaluate(detection(100), None)

    result = runtime.evaluate(detection(0), None)

    assert result.transition.changed is False
    assert runtime.state == ProtectionState.LOCKDOWN


def test_recovery_lifecycle():
    runtime = ProtectionRuntime()
    runtime.initialize()
    runtime.evaluate(detection(100), None)

    runtime.begin_recovery()
    assert runtime.state == ProtectionState.RECOVERING

    runtime.finish_recovery(success=True)
    assert runtime.state == ProtectionState.PROTECTED


def test_recovery_failure_is_explicit():
    runtime = ProtectionRuntime()
    runtime.initialize()
    runtime.evaluate(detection(100), None)

    runtime.begin_recovery()
    runtime.finish_recovery(success=False)

    assert runtime.state == ProtectionState.RECOVERY_FAILED

    runtime.begin_recovery()
    assert runtime.state == ProtectionState.RECOVERING
