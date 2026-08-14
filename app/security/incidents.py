from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from time import monotonic

from app.core.constants import SecurityEventType
from app.security.events import Detection, SecurityEvent


_DESTRUCTIVE = {
    SecurityEventType.CHANNEL_DELETE,
    SecurityEventType.ROLE_DELETE,
}

_ESCALATION = {
    SecurityEventType.ROLE_UPDATE,
    SecurityEventType.GUILD_UPDATE,
}


@dataclass(frozen=True, slots=True)
class Incident:
    """An in-memory security incident assembled from related detections."""

    key: str
    guild_id: int
    actor_id: int | None
    incident_type: str
    severity: str
    risk_score: int
    event_count: int
    summary: str
    first_seen: float
    last_seen: float


class IncidentAggregator:
    """Group related high-risk detections into bounded incidents.

    This layer is intentionally deterministic and does not call an AI model.
    Events from the same guild/actor/type are merged inside a short window;
    unknown-actor events are grouped by guild and event type until audit-log
    correlation supplies an actor.
    """

    def __init__(self, *, window_seconds: float = 15.0, max_events_per_incident: int = 256) -> None:
        self.window_seconds = window_seconds
        self.max_events_per_incident = max_events_per_incident
        self._buckets: dict[tuple[int, int | None, str], deque[Detection]] = defaultdict(deque)

    def ingest(self, detection: Detection, *, now: float | None = None) -> Incident | None:
        event = detection.event
        current = monotonic() if now is None else now
        if detection.signal.score < 60:
            return None

        key = self._bucket_key(event)
        bucket = self._buckets[key]
        self._prune(bucket, current)
        bucket.append(detection)
        while len(bucket) > self.max_events_per_incident:
            bucket.popleft()

        return self._build_incident(key, bucket, current)

    def get_open_incident(self, *, guild_id: int, actor_id: int | None, incident_type: str, now: float | None = None) -> Incident | None:
        current = monotonic() if now is None else now
        key = (guild_id, actor_id, incident_type)
        bucket = self._buckets.get(key)
        if not bucket:
            return None
        self._prune(bucket, current)
        if not bucket:
            self._buckets.pop(key, None)
            return None
        return self._build_incident(key, bucket, current)

    def _bucket_key(self, event: SecurityEvent) -> tuple[int, int | None, str]:
        return (event.guild_id, event.actor_id, self._incident_type(event.event_type))

    def _incident_type(self, event_type: SecurityEventType) -> str:
        if event_type in _DESTRUCTIVE:
            return "DESTRUCTIVE_RESOURCE_ACTIVITY"
        if event_type in _ESCALATION:
            return "PRIVILEGE_ESCALATION"
        return "SECURITY_ACTIVITY"

    def _build_incident(
        self,
        key: tuple[int, int | None, str],
        bucket: deque[Detection],
        current: float,
    ) -> Incident:
        first = bucket[0].event.timestamp
        last = bucket[-1].event.timestamp
        max_score = max(item.signal.score for item in bucket)
        event_count = len(bucket)
        protected_count = sum(1 for item in bucket if item.event.protected_target)
        score = min(100, max_score + min(25, max(0, event_count - 1) * 5) + (20 if protected_count else 0))
        severity = self._severity(score)
        incident_type = key[2]
        actor_label = str(key[1]) if key[1] is not None else "unknown"
        summary = (
            f"{incident_type} by actor {actor_label}: {event_count} related event(s), "
            f"max event risk {max_score}/100, protected targets {protected_count}."
        )
        incident_key = f"{key[0]}:{actor_label}:{incident_type}"
        return Incident(
            key=incident_key,
            guild_id=key[0],
            actor_id=key[1],
            incident_type=incident_type,
            severity=severity,
            risk_score=score,
            event_count=event_count,
            summary=summary,
            first_seen=first,
            last_seen=min(current, last) if last else current,
        )

    @staticmethod
    def _severity(score: int) -> str:
        if score >= 95:
            return "EMERGENCY"
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        if score >= 20:
            return "LOW"
        return "SAFE"

    def _prune(self, bucket: deque[Detection], now: float) -> None:
        cutoff = now - self.window_seconds
        while bucket and bucket[0].event.timestamp < cutoff:
            bucket.popleft()
