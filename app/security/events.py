from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
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
    audit_log_id: int | None = None
    event_id: str | None = None
    timestamp: float = field(default_factory=monotonic)

    @property
    def fingerprint(self) -> str:
        """Return a stable identity when Discord gives us one.

        Audit-log IDs are the preferred identity. Gateway events without an
        audit ID use the event ID when available; otherwise the short-lived
        fallback deliberately includes the event timestamp bucket.
        """
        if self.audit_log_id is not None:
            return f"audit:{self.guild_id}:{self.audit_log_id}"
        if self.event_id is not None:
            return f"gateway:{self.guild_id}:{self.event_id}"
        bucket = int(self.timestamp * 10)
        return ":".join(
            (
                "fallback",
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
        self._seen: dict[str, float] = {}

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
