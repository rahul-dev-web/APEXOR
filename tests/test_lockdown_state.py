from app.core.constants import ProtectionState
from app.security.lockdown import can_transition, should_enter_lockdown, state_for_risk


def test_risk_mapping_matches_canonical_security_states() -> None:
    assert state_for_risk(0) == ProtectionState.PROTECTED
    assert state_for_risk(59) == ProtectionState.PROTECTED
    assert state_for_risk(60) == ProtectionState.SUSPICIOUS
    assert state_for_risk(79) == ProtectionState.SUSPICIOUS
    assert state_for_risk(80) == ProtectionState.HIGH_RISK
    assert state_for_risk(94) == ProtectionState.HIGH_RISK
    assert state_for_risk(95) == ProtectionState.LOCKDOWN
    assert state_for_risk(100) == ProtectionState.LOCKDOWN


def test_lockdown_threshold_is_inclusive_and_clamped() -> None:
    assert should_enter_lockdown(79) is False
    assert should_enter_lockdown(80) is True
    assert should_enter_lockdown(101) is True
    assert should_enter_lockdown(-1) is False
    assert should_enter_lockdown(79, threshold=70) is True


def test_lockdown_cannot_downgrade_directly_to_protected() -> None:
    assert can_transition(ProtectionState.LOCKDOWN, ProtectionState.PROTECTED) is False
    assert can_transition(ProtectionState.LOCKDOWN, ProtectionState.RECOVERING) is True


def test_recovery_must_be_completed_after_entering_recovery() -> None:
    assert can_transition(ProtectionState.RECOVERING, ProtectionState.PROTECTED) is True
    assert can_transition(ProtectionState.RECOVERY_FAILED, ProtectionState.RECOVERING) is True
    assert can_transition(ProtectionState.RECOVERY_FAILED, ProtectionState.PROTECTED) is False


def test_normal_states_can_enter_lockdown() -> None:
    assert can_transition(ProtectionState.PROTECTED, ProtectionState.LOCKDOWN) is True
    assert can_transition(ProtectionState.SUSPICIOUS, ProtectionState.LOCKDOWN) is True
    assert can_transition(ProtectionState.HIGH_RISK, ProtectionState.LOCKDOWN) is True
