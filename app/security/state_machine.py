"""Deterministic guild protection state machine.

The state machine is intentionally independent of Discord, SQLAlchemy and Groq so
that security transitions remain deterministic and unit-testable.
"""

from dataclasses import dataclass

from app.core.constants import ProtectionState


class InvalidProtectionTransition(ValueError):
    """Raised when a guild attempts an unsafe/undefined state transition."""


@dataclass(frozen=True, slots=True)
class TransitionResult:
    previous: ProtectionState
    current: ProtectionState
    changed: bool


# Explicit allow-list: no implicit transitions are permitted.
_ALLOWED: dict[ProtectionState, frozenset[ProtectionState]] = {
    ProtectionState.INITIALIZING: frozenset({ProtectionState.PROTECTED, ProtectionState.DEGRADED}),
    ProtectionState.PROTECTED: frozenset({
        ProtectionState.SUSPICIOUS,
        ProtectionState.HIGH_RISK,
        ProtectionState.LOCKDOWN,
        ProtectionState.DEGRADED,
        ProtectionState.DISABLED,
    }),
    ProtectionState.DEGRADED: frozenset({
        ProtectionState.PROTECTED,
        ProtectionState.SUSPICIOUS,
        ProtectionState.HIGH_RISK,
        ProtectionState.LOCKDOWN,
        ProtectionState.DISABLED,
    }),
    ProtectionState.SUSPICIOUS: frozenset({
        ProtectionState.PROTECTED,
        ProtectionState.HIGH_RISK,
        ProtectionState.LOCKDOWN,
        ProtectionState.DEGRADED,
    }),
    ProtectionState.HIGH_RISK: frozenset({
        ProtectionState.SUSPICIOUS,
        ProtectionState.LOCKDOWN,
        ProtectionState.RECOVERING,
        ProtectionState.DEGRADED,
    }),
    ProtectionState.LOCKDOWN: frozenset({
        ProtectionState.RECOVERING,
        ProtectionState.RECOVERY_FAILED,
        ProtectionState.DEGRADED,
    }),
    ProtectionState.RECOVERING: frozenset({
        ProtectionState.PROTECTED,
        ProtectionState.DEGRADED,
        ProtectionState.RECOVERY_FAILED,
        ProtectionState.LOCKDOWN,
    }),
    ProtectionState.RECOVERY_FAILED: frozenset({
        ProtectionState.RECOVERING,
        ProtectionState.LOCKDOWN,
        ProtectionState.DEGRADED,
    }),
    ProtectionState.DISABLED: frozenset({ProtectionState.INITIALIZING}),
}


class ProtectionStateMachine:
    """Small deterministic state machine for one guild."""

    def __init__(self, state: ProtectionState = ProtectionState.INITIALIZING) -> None:
        self._state = state

    @property
    def state(self) -> ProtectionState:
        return self._state

    def can_transition(self, target: ProtectionState) -> bool:
        return target == self._state or target in _ALLOWED[self._state]

    def transition(self, target: ProtectionState) -> TransitionResult:
        if target == self._state:
            return TransitionResult(self._state, self._state, False)
        if not self.can_transition(target):
            raise InvalidProtectionTransition(
                f"Invalid APXOR protection transition: {self._state} -> {target}"
            )
        previous = self._state
        self._state = target
        return TransitionResult(previous, target, True)

    def enter_incident(self, risk_score: int) -> TransitionResult:
        """Map deterministic risk bands to protection states."""
        score = max(0, min(100, risk_score))
        if score >= 95:
            target = ProtectionState.LOCKDOWN
        elif score >= 80:
            target = ProtectionState.HIGH_RISK
        elif score >= 60:
            target = ProtectionState.SUSPICIOUS
        else:
            target = ProtectionState.PROTECTED

        # Security never silently downgrades an active containment state because
        # one low-risk event arrived later.
        if self._state in {
            ProtectionState.LOCKDOWN,
            ProtectionState.RECOVERING,
            ProtectionState.RECOVERY_FAILED,
        } and target == ProtectionState.PROTECTED:
            return TransitionResult(self._state, self._state, False)
        return self.transition(target)

    def begin_recovery(self) -> TransitionResult:
        if self._state not in {
            ProtectionState.HIGH_RISK,
            ProtectionState.LOCKDOWN,
            ProtectionState.RECOVERY_FAILED,
        }:
            raise InvalidProtectionTransition(
                f"Recovery cannot start from {self._state}"
            )
        return self.transition(ProtectionState.RECOVERING)

    def finish_recovery(self, *, success: bool, degraded: bool = False) -> TransitionResult:
        if self._state != ProtectionState.RECOVERING:
            raise InvalidProtectionTransition(
                f"Recovery cannot finish from {self._state}"
            )
        if not success:
            return self.transition(ProtectionState.RECOVERY_FAILED)
        return self.transition(
            ProtectionState.DEGRADED if degraded else ProtectionState.PROTECTED
        )

    @staticmethod
    def allowed_transitions() -> dict[ProtectionState, frozenset[ProtectionState]]:
        return dict(_ALLOWED)
