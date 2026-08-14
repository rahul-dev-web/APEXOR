from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from time import monotonic

from app.core.constants import SecurityEventType
from app.security.risk import RiskSignal, score_event


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """Normalized security event used by the deterministic detection pipeline."""

    guild_id: int
    event_type: SecurityEventType
    target_id: int | None = None
    actor_id: int | None = None
    protected_target: bool = False
    timestamp: float = 0.0

    @property
    def fingerprint(self) -> str:
        # Gateway events do not always expose an audit entry ID. This fingerprint
        # is intentionally stable for short-lived duplicate-event suppression.
        bucket = int(self.timestamp * 10)
        return ":".join(
            (
                str(self.guild_id),
                self.event_type.value,
                str(self.target_id or 0),
                str(self.actor_id or 0),
                str(bucket),
            )
        )


@dataclass(frozen=True, slots=True)
class Detection:
    event: SecurityEvent
    signal: RiskSignal
    velocity_count: int
    velocity_window_seconds: float


class EventCorrelator:
    """Deterministic short-window correlator.

    Actor-specific counters are preferred. If an actor is not known yet (normal
    for several Gateway events), events are still normalized but are not merged
    into an actor-specific attack score. Audit-log correlation can later attach
    the actor and replay the event safely.
    """

    def __init__(self, *, window_seconds: float = 10.0, max_events: int = 256) -> None:
        self.window_seconds = window_seconds
        self.max_events = max_events
        self._actor_events: dict[tuple[int, int, SecurityEventType], deque[float]] = defaultdict(deque)
        self._seen: dict[int, float] = {}

    def process(self, event: SecurityEvent, *, now: float | None = None) -> Detection:
        current = monotonic() if now is None else now
        self._prune_seen(current)

        signal = score_event(event.event_type, protected_target=event.protected_target)
        if event.fingerprint in self._seen:
            return Detection(event, signal, velocity_count=0, velocity_window_seconds=self.window_seconds)

        self._seen[event.fingerprint] = current
        count = 1

        if event.actor_id is not None:
            key = (event.guild_id, event.actor_id, event.event_type)
            bucket = self._actor_events[key]
            bucket.append(current)
            self._prune_bucket(bucket, current)
            while len(bucket) > self.max_events:
                bucket.popleft()
            count = len(bucket)

        # Velocity escalation is deterministic and additive. These thresholds
        # are intentionally conservative and can be tuned after attack tests.
        velocity_bonus = self._velocity_bonus(event.event_type, count)
        combined = RiskSignal(
            score=min(signal.score + velocity_bonus, 100),
            reason=signal.reason + (f":velocity_{count}" if velocity_bonus else ""),
        )
        return Detection(event, combined, count, self.window_seconds)

    def _velocity_bonus(self, event_type: SecurityEventType, count: int) -> int:
        if event_type in {SecurityEventType.CHANNEL_DELETE, SecurityEventType.ROLE_DELETE}:
            if count >= 10:
                return 60
            if count >= 5:
                return 40
            if count >= 3:
                return 20
        if event_type in {SecurityEventType.CHANNEL_CREATE, SecurityEventType.ROLE_CREATE}:
            if count >= 10:
                return 30
            if count >= 5:
                return 15
        if event_type in {SecurityEventType.ROLE_UPDATE, SecurityEventType.GUILD_UPDATE}:
            if count >= 5:
                return 25
        return 0

    def _prune_bucket(self, bucket: deque[float], now: float) -> None:
        cutoff = now - self.window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

    def _prune_seen(self, now: float) -> None:
        cutoff = now - self.window_seconds
        stale = [fingerprint for fingerprint, timestamp in self._seen.items() if timestamp < cutoff]
        for fingerprint in stale:
            del self._seen[fingerprint]
