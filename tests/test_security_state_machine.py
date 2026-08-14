import pytest

from app.core.constants import ProtectionState
from app.security.state_machine import InvalidProtectionTransition, ProtectionStateMachine


def test_initialization_can_become_protected():
    machine = ProtectionStateMachine()
    result = machine.transition(ProtectionState.PROTECTED)

    assert result.changed is True
    assert result.previous == ProtectionState.INITIALIZING
    assert machine.state == ProtectionState.PROTECTED


def test_invalid_transition_is_rejected():
    machine = ProtectionStateMachine(ProtectionState.INITIALIZING)

    with pytest.raises(InvalidProtectionTransition):
        machine.transition(ProtectionState.LOCKDOWN)


def test_risk_escalation_is_deterministic():
    machine = ProtectionStateMachine(ProtectionState.PROTECTED)

    machine.enter_incident(60)
    assert machine.state == ProtectionState.SUSPICIOUS

    machine.enter_incident(80)
    assert machine.state == ProtectionState.HIGH_RISK

    machine.enter_incident(95)
    assert machine.state == ProtectionState.LOCKDOWN


def test_low_risk_event_cannot_clear_lockdown():
    machine = ProtectionStateMachine(ProtectionState.PROTECTED)
    machine.enter_incident(100)

    result = machine.enter_incident(0)

    assert result.changed is False
    assert machine.state == ProtectionState.LOCKDOWN


def test_recovery_success_returns_to_protected():
    machine = ProtectionStateMachine(ProtectionState.PROTECTED)
    machine.enter_incident(100)
    machine.begin_recovery()

    assert machine.state == ProtectionState.RECOVERING
    machine.finish_recovery(success=True)
    assert machine.state == ProtectionState.PROTECTED


def test_recovery_failure_requires_explicit_retry():
    machine = ProtectionStateMachine(ProtectionState.LOCKDOWN)
    machine.begin_recovery()
    machine.finish_recovery(success=False)

    assert machine.state == ProtectionState.RECOVERY_FAILED
    machine.begin_recovery()
    assert machine.state == ProtectionState.RECOVERING


def test_recovery_can_finish_degraded():
    machine = ProtectionStateMachine(ProtectionState.HIGH_RISK)
    machine.begin_recovery()
    machine.finish_recovery(success=True, degraded=True)

    assert machine.state == ProtectionState.DEGRADED
