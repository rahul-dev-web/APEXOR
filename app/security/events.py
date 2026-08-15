from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from time import monotonic

from app.core.constants import SecurityEventType
from app.security.risk import RiskSignal, score_event


DESTRUCTIVE_EVENTS = frozenset(
    {
        SecurityEventType.CHANNEL_DELETE,
        SecurityEventType.ROLE_DELETE,
        SecurityEventType.CHANNEL_UPDATE,
        SecurityEventType.ROLE_UPDATE,
        SecurityEventType.GUILD_UPDATE,
        SecurityEventType.MEMBER_REMOVE,
        SecurityEventType.KICK,
        SecurityEventType.BAN_ADD,
        SecurityEventType.WEBHOOK_UPDATE,
        SecurityEventType.INTEGRATION_UPDATE,
    }
)


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
    permission_added: tuple[str, ...] = ()
    permission_removed: tuple[str, ...] = ()

    @property
    def fingerprint(self) -> str:
        if self.audit_log_id is not None:
            return f"audit:{self.guild_id}:{self.audit_log_id}"
        if self.event_id is not None:
            return f"gateway:{self.guild_id}:{self.event_id}"
        bucket = int(self.timestamp * 10)
        return ":".join(("fallback", str(self.guild_id), self.event_type.value, str(self.target_id or 0), str(self.actor_id or 0), str(bucket)))


@dataclass(frozen=True, slots=True)
class Detection:
    event: SecurityEvent
    signal: RiskSignal
    velocity_count: int
    velocity_window_seconds: float


class EventCorrelator:
    """Deterministic short-window correlator for anti-nuke behavior."""

    def __init__(self, *, window_seconds: float = 10.0, max_events: int = 256) -> None:
        self.window_seconds = window_seconds
        self.max_events = max_events
        self._actor_events: dict[tuple[int, int, SecurityEventType], deque[float]] = defaultdict(deque)
        self._actor_destructive_events: dict[tuple[int, int], deque[tuple[float, SecurityEventType]]] = defaultdict(deque)
        self._seen: dict[str, float] = {}

    def process(self, event: SecurityEvent, *, now: float | None = None) -> Detection:
        current = monotonic() if now is None else now
        self._prune_seen(current)
        signal = score_event(
            event.event_type,
            protected_target=event.protected_target,
            permission_added=event.permission_added,
        )
        if event.fingerprint in self._seen:
            return Detection(event, signal, velocity_count=0, velocity_window_seconds=self.window_seconds)

        self._seen[event.fingerprint] = current
        count = 1
        mixed_count = 0
        mixed_types = 0
        if event.actor_id is not None:
            key = (event.guild_id, event.actor_id, event.event_type)
            bucket = self._actor_events[key]
            bucket.append(current)
            self._prune_bucket(bucket, current)
            while len(bucket) > self.max_events:
                bucket.popleft()
            count = len(bucket)

            if event.event_type in DESTRUCTIVE_EVENTS:
                destructive_bucket = self._actor_destructive_events[(event.guild_id, event.actor_id)]
                destructive_bucket.append((current, event.event_type))
                self._prune_destructive_bucket(destructive_bucket, current)
                while len(destructive_bucket) > self.max_events:
                    destructive_bucket.popleft()
                mixed_count = len(destructive_bucket)
                mixed_types = len({event_type for _, event_type in destructive_bucket})

        velocity_bonus = self._velocity_bonus(event.event_type, count)
        mixed_bonus = self._mixed_attack_bonus(mixed_count, mixed_types)
        reasons = signal.reason
        if velocity_bonus:
            reasons += f":velocity_{count}"
        if mixed_count >= 3:
            reasons += f":destructive_window_{mixed_count}"
        return Detection(
            event,
            RiskSignal(score=min(signal.score + velocity_bonus + mixed_bonus, 100), reason=reasons),
            count,
            self.window_seconds,
        )

    def _velocity_bonus(self, event_type: SecurityEventType, count: int) -> int:
        if event_type in {SecurityEventType.CHANNEL_DELETE, SecurityEventType.ROLE_DELETE}:
            if count >= 10:
                return 60
            if count >= 5:
                return 50
            if count >= 3:
                return 30
        if event_type in {SecurityEventType.CHANNEL_CREATE, SecurityEventType.ROLE_CREATE}:
            if count >= 10:
                return 30
            if count >= 5:
                return 15
        if event_type in {
            SecurityEventType.ROLE_UPDATE,
            SecurityEventType.GUILD_UPDATE,
            SecurityEventType.MEMBER_REMOVE,
            SecurityEventType.KICK,
            SecurityEventType.BAN_ADD,
            SecurityEventType.WEBHOOK_UPDATE,
            SecurityEventType.INTEGRATION_UPDATE,
        }:
            if count >= 5:
                return 25
            if count >= 3:
                return 10
        return 0

    @staticmethod
    def _mixed_attack_bonus(count: int, distinct_types: int) -> int:
        """Escalate mixed destructive behavior, not repeated copies of one action."""
        if distinct_types < 2:
            return 0
        if count >= 10:
            return 30
        if count >= 5:
            return 20
        if count >= 3:
            return 10
        return 0

    def _prune_bucket(self, bucket: deque[float], now: float) -> None:
        cutoff = now - self.window_seconds
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

    def _prune_destructive_bucket(self, bucket: deque[tuple[float, SecurityEventType]], now: float) -> None:
        cutoff = now - self.window_seconds
        while bucket and bucket[0][0] <= cutoff:
            bucket.popleft()

    def _prune_seen(self, now: float) -> None:
        cutoff = now - self.window_seconds
        stale = [fingerprint for fingerprint, timestamp in self._seen.items() if timestamp <= cutoff]
        for fingerprint in stale:
            del self._seen[fingerprint]
