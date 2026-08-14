from __future__ import annotations

from dataclasses import dataclass

from app.core.constants import ProtectionState
from app.models.security import SecurityConfig
from app.security.decision_runtime import DecisionRuntime, resolve_decision
from app.security.events import Detection
from app.security.state_machine import ProtectionStateMachine, TransitionResult


@dataclass(frozen=True, slots=True)
class ProtectionRuntimeResult:
    """Deterministic decision plus the resulting guild protection transition."""

    decision: DecisionRuntime
    transition: TransitionResult

    @property
    def state(self) -> ProtectionState:
        return self.transition.current

    @property
    def should_lockdown(self) -> bool:
        return self.decision.should_lockdown or self.state == ProtectionState.LOCKDOWN

    @property
    def should_recover(self) -> bool:
        return self.decision.should_recover


class ProtectionRuntime:
    """Bridge the stateless policy decision into a persistent guild lifecycle.

    Discord, database, notification and recovery side effects stay outside this
    class. This keeps the security transition deterministic and makes the
    lifecycle straightforward to unit-test before wiring it into the Gateway
    event handler.
    """

    def __init__(self, state: ProtectionState = ProtectionState.INITIALIZING) -> None:
        self.machine = ProtectionStateMachine(state)

    @property
    def state(self) -> ProtectionState:
        return self.machine.state

    def initialize(self, *, degraded: bool = False) -> TransitionResult:
        target = ProtectionState.DEGRADED if degraded else ProtectionState.PROTECTED
        return self.machine.transition(target)

    def evaluate(self, detection: Detection, config: SecurityConfig | None) -> ProtectionRuntimeResult:
        decision = resolve_decision(detection, config)
        transition = self.machine.enter_incident(detection.signal.score)
        return ProtectionRuntimeResult(decision=decision, transition=transition)

    def begin_recovery(self) -> TransitionResult:
        return self.machine.begin_recovery()

    def finish_recovery(self, *, success: bool, degraded: bool = False) -> TransitionResult:
        return self.machine.finish_recovery(success=success, degraded=degraded)
