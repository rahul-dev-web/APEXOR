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
    """Bridge policy decisions into the deterministic guild lifecycle.

    The policy decision remains configuration-aware, while the lifecycle is
    enforced by the explicit state machine. Discord, database, notification and
    recovery side effects stay outside this class.
    """

    def __init__(self, state: ProtectionState = ProtectionState.INITIALIZING) -> None:
        self.machine = ProtectionStateMachine(state)

    @property
    def state(self) -> ProtectionState:
        return self.machine.state

    def initialize(self, *, degraded: bool = False) -> TransitionResult:
        target = ProtectionState.DEGRADED if degraded else ProtectionState.PROTECTED
        return self.machine.transition(target)

    def evaluate(
        self, detection: Detection, config: SecurityConfig | None
    ) -> ProtectionRuntimeResult:
        decision = resolve_decision(detection, config)

        # The decision policy can request containment before the normal risk
        # state reaches LOCKDOWN (for example, a protected-resource deletion).
        # The persisted lifecycle must reflect the actual containment state.
        target = ProtectionState.LOCKDOWN if decision.should_lockdown else decision.state

        # Never let a later low-risk event clear active containment/recovery.
        if self.machine.state in {
            ProtectionState.LOCKDOWN,
            ProtectionState.RECOVERING,
            ProtectionState.RECOVERY_FAILED,
        } and target == ProtectionState.PROTECTED:
            transition = TransitionResult(self.machine.state, self.machine.state, False)
        else:
            transition = self.machine.transition(target)

        return ProtectionRuntimeResult(decision=decision, transition=transition)

    def begin_recovery(self) -> TransitionResult:
        return self.machine.begin_recovery()

    def finish_recovery(
        self, *, success: bool, degraded: bool = False
    ) -> TransitionResult:
        return self.machine.finish_recovery(success=success, degraded=degraded)
