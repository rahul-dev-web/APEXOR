from dataclasses import dataclass

from app.core.constants import SecurityEventType


@dataclass(frozen=True)
class RiskSignal:
    score: int
    reason: str


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

PERMISSION_ESCALATION_SCORES: dict[str, int] = {
    "administrator": 95,
    "manage_guild": 85,
    "manage_channels": 85,
    "manage_roles": 85,
    "manage_webhooks": 80,
    "ban_members": 65,
    "kick_members": 60,
    "moderate_members": 60,
    "manage_messages": 55,
    "manage_threads": 50,
    "manage_nicknames": 45,
}


def score_event(
    event_type: SecurityEventType,
    *,
    protected_target: bool = False,
    permission_added: tuple[str, ...] = (),
) -> RiskSignal:
    score = EVENT_WEIGHTS.get(event_type, 0)
    reasons = [event_type.value]

    if protected_target:
        score += 40
        reasons.append("protected_target")

    if permission_added:
        normalized = tuple(sorted(set(permission_added)))
        escalation_scores = [PERMISSION_ESCALATION_SCORES[name] for name in normalized if name in PERMISSION_ESCALATION_SCORES]
        if escalation_scores:
            score = max(score, max(escalation_scores))
            reasons.append("permission_grant=" + ",".join(normalized))

    return RiskSignal(score=min(score, 100), reason=":".join(reasons))


def combine_signals(signals: list[RiskSignal]) -> int:
    return min(sum(signal.score for signal in signals), 100)
