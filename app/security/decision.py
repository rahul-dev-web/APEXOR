from __future__ import annotations

from dataclasses import dataclass

from app.core.constants import ProtectionState, SecurityEventType
from app.security.events import Detection


@dataclass(frozen=True, slots=True)
class SecurityDecision:
    """Deterministic decision produced after event correlation.

    This is deliberately policy-only: it does not call Discord, the database,
    or an AI model. That keeps the security boundary deterministic and makes
    the event-to-action policy independently testable.
    """

    state: ProtectionState
    severity: str | None
    should_lockdown: bool
    should_analyze_with_ai: bool
    should_recover: bool
    recovery_resource_type: str | None
    recovery_priority: int | None
    risk_score: int


def decide(
    detection: Detection,
    *,
    high_threshold: int = 60,
    critical_threshold: int = 80,
    emergency_threshold: int = 95,
    lockdown_enabled: bool = True,
    recovery_enabled: bool = True,
) -> SecurityDecision:
    """Translate a detection into deterministic security policy decisions."""
    score = max(0, min(detection.signal.score, 100))
    event = detection.event

    state = (
        ProtectionState.LOCKDOWN
        if score >= emergency_threshold
        else ProtectionState.HIGH_RISK
        if score >= critical_threshold
        else ProtectionState.SUSPICIOUS
        if score >= high_threshold
        else ProtectionState.PROTECTED
    )

    if score >= emergency_threshold:
        severity = "EMERGENCY"
    elif score >= critical_threshold:
        severity = "CRITICAL"
    elif score >= high_threshold:
        severity = "HIGH"
    else:
        severity = None

    lockdown_threshold = critical_threshold
    if event.protected_target and event.event_type in {
        SecurityEventType.CHANNEL_DELETE,
        SecurityEventType.ROLE_DELETE,
        SecurityEventType.ROLE_UPDATE,
    }:
        lockdown_threshold = min(lockdown_threshold, high_threshold)

    should_lockdown = lockdown_enabled and score >= lockdown_threshold
    should_analyze = score >= high_threshold

    recovery_resource_type: str | None = None
    recovery_priority: int | None = None
    if recovery_enabled and score >= high_threshold:
        if event.event_type == SecurityEventType.CHANNEL_DELETE:
            recovery_resource_type = "CHANNEL"
        elif event.event_type == SecurityEventType.ROLE_DELETE:
            recovery_resource_type = "ROLE"
        if recovery_resource_type is not None:
            recovery_priority = 10 if event.protected_target else 50

    return SecurityDecision(
        state=state,
        severity=severity,
        should_lockdown=should_lockdown,
        should_analyze_with_ai=should_analyze,
        should_recover=recovery_resource_type is not None,
        recovery_resource_type=recovery_resource_type,
        recovery_priority=recovery_priority,
        risk_score=score,
    )
