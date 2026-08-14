from app.core.constants import ProtectionState
from app.security.lockdown import can_transition, should_enter_lockdown, state_for_risk


def test_risk_state_mapping_is_deterministic():
    assert state_for_risk(0) == ProtectionState.PROTECTED
    assert state_for_risk(59) == ProtectionState.PROTECTED
    assert state_for_risk(60) == ProtectionState.SUSPICIOUS
    assert state_for_risk(79) == ProtectionState.SUSPICIOUS
    assert state_for_risk(80) == ProtectionState.HIGH_RISK
    assert state_for_risk(94) == ProtectionState.HIGH_RISK
    assert state_for_risk(95) == ProtectionState.LOCKDOWN
    assert state_for_risk(100) == ProtectionState.LOCKDOWN


def test_lockdown_containment_threshold_is_explicit():
    assert not should_enter_lockdown(79)
    assert should_enter_lockdown(80)
    assert should_enter_lockdown(100)


def test_lockdown_cannot_downgrade_directly_to_protected():
    assert can_transition(ProtectionState.HIGH_RISK, ProtectionState.LOCKDOWN)
    assert can_transition(ProtectionState.LOCKDOWN, ProtectionState.RECOVERING)
    assert not can_transition(ProtectionState.LOCKDOWN, ProtectionState.PROTECTED)


def test_recovery_failed_requires_recovery_path():
    assert can_transition(ProtectionState.RECOVERY_FAILED, ProtectionState.RECOVERING)
    assert can_transition(ProtectionState.RECOVERY_FAILED, ProtectionState.LOCKDOWN)
    assert not can_transition(ProtectionState.RECOVERY_FAILED, ProtectionState.PROTECTED)
