from dataclasses import dataclass

from app.core.constants import SecurityEventType


@dataclass(frozen=True)
class RiskSignal:
    score: int
    reason: str


# Deterministic baseline weights. These are intentionally conservative and
# will be expanded as the event correlator gains historical context.
EVENT_WEIGHTS: dict[SecurityEventType, int] = {
    SecurityEventType.CHANNEL_CREATE: 5,
    SecurityEventType.CHANNEL_UPDATE: 5,
    SecurityEventType.CHANNEL_DELETE: 25,
    SecurityEventType.ROLE_CREATE: 10,
    SecurityEventType.ROLE_UPDATE: 20,
    SecurityEventType.ROLE_DELETE: 30,
    SecurityEventType.GUILD_UPDATE: 20,
    SecurityEventType.MEMBER_UPDATE: 10,
    SecurityEventType.MEMBER_REMOVE: 15,
    SecurityEventType.KICK: 20,
    SecurityEventType.BAN_ADD: 30,
    SecurityEventType.BAN_REMOVE: 5,
    SecurityEventType.WEBHOOK_UPDATE: 20,
    SecurityEventType.INTEGRATION_UPDATE: 30,
}


def score_event(event_type: SecurityEventType, *, protected_target: bool = False) -> RiskSignal:
    score = EVENT_WEIGHTS.get(event_type, 0)
    reasons = [event_type.value]

    if protected_target:
        score += 40
        reasons.append("protected_target")

    return RiskSignal(score=min(score, 100), reason=":".join(reasons))


def combine_signals(signals: list[RiskSignal]) -> int:
    """Combine correlated signals without allowing a score above 100."""
    return min(sum(signal.score for signal in signals), 100)
