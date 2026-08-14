from app.core.constants import ProtectionState
from app.security.lockdown import can_transition, state_for_risk


def test_lockdown_state_machine_allows_expected_escalation_and_recovery() -> None:
    assert can_transition(ProtectionState.PROTECTED, ProtectionState.SUSPICIOUS)
    assert can_transition(ProtectionState.SUSPICIOUS, ProtectionState.HIGH_RISK)
    assert can_transition(ProtectionState.HIGH_RISK, ProtectionState.LOCKDOWN)
    assert can_transition(ProtectionState.LOCKDOWN, ProtectionState.RECOVERING)
    assert can_transition(ProtectionState.RECOVERING, ProtectionState.PROTECTED)


def test_lockdown_cannot_be_downgraded_by_a_benign_event() -> None:
    assert not can_transition(ProtectionState.LOCKDOWN, ProtectionState.PROTECTED)
    assert not can_transition(ProtectionState.LOCKDOWN, ProtectionState.SUSPICIOUS)
    assert not can_transition(ProtectionState.RECOVERY_FAILED, ProtectionState.PROTECTED)


def test_explicit_recovery_paths_are_available() -> None:
    assert can_transition(ProtectionState.RECOVERY_FAILED, ProtectionState.RECOVERING)
    assert can_transition(ProtectionState.RECOVERY_FAILED, ProtectionState.LOCKDOWN)
    assert can_transition(ProtectionState.DISABLED, ProtectionState.INITIALIZING)


def test_risk_mapping_remains_deterministic() -> None:
    assert state_for_risk(0) == ProtectionState.PROTECTED
    assert state_for_risk(60) == ProtectionState.SUSPICIOUS
    assert state_for_risk(80) == ProtectionState.HIGH_RISK
    assert state_for_risk(95) == ProtectionState.LOCKDOWN
