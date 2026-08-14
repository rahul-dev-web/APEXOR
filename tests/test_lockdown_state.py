from app.core.constants import ProtectionState
from app.security.lockdown import should_enter_lockdown, state_for_risk


def test_state_for_risk_boundaries() -> None:
    assert state_for_risk(0) == ProtectionState.PROTECTED
    assert state_for_risk(59) == ProtectionState.PROTECTED
    assert state_for_risk(60) == ProtectionState.SUSPICIOUS
    assert state_for_risk(79) == ProtectionState.SUSPICIOUS
    assert state_for_risk(80) == ProtectionState.HIGH_RISK
    assert state_for_risk(94) == ProtectionState.HIGH_RISK
    assert state_for_risk(95) == ProtectionState.LOCKDOWN
    assert state_for_risk(100) == ProtectionState.LOCKDOWN


def test_lockdown_threshold_is_configurable() -> None:
    assert should_enter_lockdown(79) is False
    assert should_enter_lockdown(80) is True
    assert should_enter_lockdown(79, threshold=70) is True
