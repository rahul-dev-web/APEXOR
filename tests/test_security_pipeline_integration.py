from types import SimpleNamespace

import pytest

from app.core.constants import ProtectionState, SecurityEventType
from app.security.decision_runtime import resolve_decision
from app.security.events import Detection, SecurityEvent
from app.security.risk import RiskSignal


def _config():
    return SimpleNamespace(
        risk_threshold_high=60,
        risk_threshold_critical=80,
        risk_threshold_emergency=95,
        lockdown_enabled=True,
        recovery_enabled=True,
    )


def _detection(
    score: int,
    event_type: SecurityEventType,
    *,
    protected: bool = False,
) -> Detection:
    return Detection(
        event=SecurityEvent(
            guild_id=1,
            actor_id=42,
            target_id=99,
            event_type=event_type,
            protected_target=protected,
        ),
        signal=RiskSignal(score=score, reason="integration test"),
        velocity_count=1,
        velocity_window_seconds=10,
    )


@pytest.mark.parametrize(
    ("score", "expected_state", "expected_severity"),
    [
        (0, ProtectionState.PROTECTED, None),
        (59, ProtectionState.PROTECTED, None),
        (60, ProtectionState.SUSPICIOUS, "HIGH"),
        (80, ProtectionState.HIGH_RISK, "CRITICAL"),
        (95, ProtectionState.LOCKDOWN, "EMERGENCY"),
        (100, ProtectionState.LOCKDOWN, "EMERGENCY"),
    ],
)
def test_event_to_decision_risk_bands(score, expected_state, expected_severity):
    runtime = resolve_decision(
        _detection(score, SecurityEventType.CHANNEL_UPDATE),
        _config(),
    )

    assert runtime.state == expected_state
    assert runtime.decision.severity == expected_severity
    assert runtime.decision.risk_score == score


def test_protected_channel_delete_enters_lockdown_and_recovery():
    runtime = resolve_decision(
        _detection(60, SecurityEventType.CHANNEL_DELETE, protected=True),
        _config(),
    )

    assert runtime.state == ProtectionState.SUSPICIOUS
    assert runtime.should_lockdown is True
    assert runtime.should_analyze_with_ai is True
    assert runtime.should_recover is True
    assert runtime.decision.recovery_resource_type == "CHANNEL"
    assert runtime.decision.recovery_priority == 10


def test_protected_role_update_is_contained_without_ai_authority():
    runtime = resolve_decision(
        _detection(75, SecurityEventType.ROLE_UPDATE, protected=True),
        _config(),
    )

    assert runtime.should_lockdown is True
    assert runtime.should_analyze_with_ai is True
    assert runtime.should_recover is False
    assert runtime.decision.recovery_resource_type is None


def test_emergency_role_delete_requests_role_recovery():
    runtime = resolve_decision(
        _detection(99, SecurityEventType.ROLE_DELETE),
        _config(),
    )

    assert runtime.state == ProtectionState.LOCKDOWN
    assert runtime.should_lockdown is True
    assert runtime.should_recover is True
    assert runtime.decision.recovery_resource_type == "ROLE"
    assert runtime.decision.recovery_priority == 50


def test_recovery_can_be_disabled_without_disabling_lockdown():
    config = _config()
    config.recovery_enabled = False

    runtime = resolve_decision(
        _detection(99, SecurityEventType.CHANNEL_DELETE),
        config,
    )

    assert runtime.state == ProtectionState.LOCKDOWN
    assert runtime.should_lockdown is True
    assert runtime.should_analyze_with_ai is True
    assert runtime.should_recover is False


def test_lockdown_can_be_disabled_by_policy():
    config = _config()
    config.lockdown_enabled = False

    runtime = resolve_decision(
        _detection(99, SecurityEventType.CHANNEL_DELETE),
        config,
    )

    assert runtime.state == ProtectionState.LOCKDOWN
    assert runtime.should_lockdown is False
    assert runtime.should_analyze_with_ai is True
    assert runtime.should_recover is True
