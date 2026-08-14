"""Deterministic sliding-window velocity detection for anti-nuke events."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.core.constants import SecurityEventType


@dataclass(frozen=True)
class VelocitySignal:
    count: int
    window_seconds: int
    score_bonus: int
    reason: str


# Destructive operations receive stronger velocity bonuses.
DESTRUCTIVE_EVENTS = frozenset(
    {
        SecurityEventType.CHANNEL_DELETE,
        SecurityEventType.ROLE_DELETE,
        SecurityEventType.BAN_ADD,
        SecurityEventType.KICK,
    }
)


class VelocityTracker:
    """Track per-guild/per-actor event velocity in bounded sliding windows.

    This component is deliberately deterministic and in-memory. Persistence and
    distributed coordination can be layered on later without changing the API.
    """

    def __init__(self, *, max_window_seconds: int = 60, max_events_per_key: int = 256) -> None:
        if max_window_seconds <= 0:
            raise ValueError("max_window_seconds must be positive")
        if max_events_per_key <= 0:
            raise ValueError("max_events_per_key must be positive")
        self.max_window = timedelta(seconds=max_window_seconds)
        self.max_events_per_key = max_events_per_key
        self._events: dict[tuple[int, int, SecurityEventType], deque[datetime]] = defaultdict(deque)

    def record(
        self,
        guild_id: int,
        actor_id: int,
        event_type: SecurityEventType,
        *,
        occurred_at: datetime | None = None,
    ) -> VelocitySignal:
        now = occurred_at or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        key = (guild_id, actor_id, event_type)
        events = self._events[key]
        cutoff = now - self.max_window

        while events and events[0] < cutoff:
            events.popleft()

        events.append(now)
        while len(events) > self.max_events_per_key:
            events.popleft()

        count = len(events)
        bonus = self._score_bonus(event_type, count)
        reason = f"velocity:{event_type.value}:{count}/{int(self.max_window.total_seconds())}s"
        return VelocitySignal(count, int(self.max_window.total_seconds()), bonus, reason)

    @staticmethod
    def _score_bonus(event_type: SecurityEventType, count: int) -> int:
        if count < 2:
            return 0
        if event_type in DESTRUCTIVE_EVENTS:
            if count >= 10:
                return 70
            if count >= 5:
                return 50
            if count >= 3:
                return 25
            return 10
        if count >= 10:
            return 45
        if count >= 5:
            return 25
        if count >= 3:
            return 10
        return 5

    def clear_actor(self, guild_id: int, actor_id: int) -> None:
        for key in tuple(self._events):
            if key[0] == guild_id and key[1] == actor_id:
                del self._events[key]

    def clear_guild(self, guild_id: int) -> None:
        for key in tuple(self._events):
            if key[0] == guild_id:
                del self._events[key]
