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


DESTRUCTIVE_EVENTS = frozenset(
    {
        SecurityEventType.CHANNEL_DELETE,
        SecurityEventType.ROLE_DELETE,
        SecurityEventType.BAN_ADD,
        SecurityEventType.KICK,
    }
)


class VelocityTracker:
    """Track per-guild/per-actor event velocity in bounded sliding windows."""

    def __init__(self, *, max_window_seconds: int = 60, max_events_per_key: int = 256) -> None:
        if max_window_seconds <= 0:
            raise ValueError("max_window_seconds must be positive")
        if max_events_per_key <= 0:
            raise ValueError("max_events_per_key must be positive")
        self.max_window = timedelta(seconds=max_window_seconds)
        self.max_events_per_key = max_events_per_key
        self._events: dict[tuple[int, int, SecurityEventType], deque[datetime]] = defaultdict(deque)
        self._actor_events: dict[tuple[int, int], deque[tuple[datetime, SecurityEventType]]] = defaultdict(deque)

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

        actor_key = (guild_id, actor_id)
        actor_events = self._actor_events[actor_key]
        while actor_events and actor_events[0][0] < cutoff:
            actor_events.popleft()
        actor_events.append((now, event_type))
        while len(actor_events) > self.max_events_per_key:
            actor_events.popleft()

        count = len(events)
        same_type_bonus = self._score_bonus(event_type, count)
        destructive_count = sum(1 for _, kind in actor_events if kind in DESTRUCTIVE_EVENTS)
        destructive_types = {kind for _, kind in actor_events if kind in DESTRUCTIVE_EVENTS}
        mixed_bonus = self._mixed_destructive_bonus(destructive_count, len(destructive_types))
        bonus = min(same_type_bonus + mixed_bonus, 100)

        reason = f"velocity:{event_type.value}:{count}/{int(self.max_window.total_seconds())}s"
        if mixed_bonus:
            reason += f":mixed_destructive={destructive_count}/{len(destructive_types)}"
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

    @staticmethod
    def _mixed_destructive_bonus(destructive_count: int, destructive_types: int) -> int:
        """Escalate attacks that rotate destructive operation types in one window."""
        if destructive_count >= 6 and destructive_types >= 3:
            return 35
        if destructive_count >= 4 and destructive_types >= 2:
            return 20
        if destructive_count >= 3 and destructive_types >= 2:
            return 10
        return 0

    def clear_actor(self, guild_id: int, actor_id: int) -> None:
        for key in tuple(self._events):
            if key[0] == guild_id and key[1] == actor_id:
                del self._events[key]
        self._actor_events.pop((guild_id, actor_id), None)

    def clear_guild(self, guild_id: int) -> None:
        for key in tuple(self._events):
            if key[0] == guild_id:
                del self._events[key]
        for key in tuple(self._actor_events):
            if key[0] == guild_id:
                del self._actor_events[key]
