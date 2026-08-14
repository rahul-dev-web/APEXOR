from __future__ import annotations

from dataclasses import dataclass

from app.core.constants import ProtectionState
from app.models.security import SecurityConfig
from app.security.decision import SecurityDecision, decide
from app.security.events import Detection


@dataclass(frozen=True, slots=True)
class DecisionRuntime:
    """Resolve persisted guild policy into a deterministic security decision.

    This adapter is intentionally free of Discord/DB side effects. The bot
    event pipeline can use it as the single policy boundary before invoking
    lockdown, notifications, AI, or recovery services.
    """

    decision: SecurityDecision

    @property
    def state(self) -> ProtectionState:
        return self.decision.state

    @property
    def should_lockdown(self) -> bool:
        return self.decision.should_lockdown

    @property
    def should_analyze_with_ai(self) -> bool:
        return self.decision.should_analyze_with_ai

    @property
    def should_recover(self) -> bool:
        return self.decision.should_recover


def resolve_decision(detection: Detection, config: SecurityConfig | None) -> DecisionRuntime:
    """Build the only deterministic policy decision used by the event path."""
    decision = decide(
        detection,
        high_threshold=config.risk_threshold_high if config else 60,
        critical_threshold=config.risk_threshold_critical if config else 80,
        emergency_threshold=config.risk_threshold_emergency if config else 95,
        lockdown_enabled=config.lockdown_enabled if config else True,
        recovery_enabled=config.recovery_enabled if config else True,
    )
    return DecisionRuntime(decision=decision)
