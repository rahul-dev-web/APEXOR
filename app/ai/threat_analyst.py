from __future__ import annotations

import hashlib
import json
import logging
from time import monotonic
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.core.config import settings
from app.security.events import Detection

logger = logging.getLogger(__name__)
PROMPT_VERSION = "threat-analyst-v1"


class ThreatAssessment(BaseModel):
    """Advisory AI assessment; it cannot authorize Discord mutations."""

    model_config = ConfigDict(extra="forbid")

    classification: Literal["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL", "EMERGENCY"]
    confidence: float = Field(ge=0, le=1)
    reason: str = Field(min_length=1, max_length=1000)
    recommended_action: Literal["OBSERVE", "ALERT", "LOCKDOWN", "RECOVERY_REVIEW", "RECOVER", "ESCALATE"]
    notify_owner: bool


class GroqThreatAnalyst:
    """Optional Groq analyst using strict JSON-schema output."""

    DEFAULT_MODEL = "openai/gpt-oss-20b"

    def __init__(self, *, api_key: str | None = None, model: str | None = None) -> None:
        self.api_key = api_key if api_key is not None else settings.groq_api_key
        self.model = model or settings.groq_model or self.DEFAULT_MODEL
        self._client: Any | None = None

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def _get_client(self) -> Any:
        if not self.available:
            raise RuntimeError("GROQ_API_KEY is not configured")
        if self._client is None:
            from groq import Groq
            self._client = Groq(api_key=self.api_key)
        return self._client

    async def assess(self, incident: dict[str, Any]) -> ThreatAssessment | None:
        if not self.available:
            return None
        import asyncio
        try:
            return await asyncio.to_thread(self._assess_sync, incident)
        except Exception:
            logger.exception("Groq threat assessment failed")
            return None

    def _assess_sync(self, incident: dict[str, Any]) -> ThreatAssessment:
        client = self._get_client()
        schema = ThreatAssessment.model_json_schema()
        prompt = (
            "You are APEXOR's advisory Discord security analyst. Analyze only the supplied "
            "security incident. Do not invent events. The deterministic APEXOR policy engine "
            "is authoritative. You cannot execute tools, modify Discord, or override policy. "
            "Return a concise classification and explanation.\n\n"
            f"INCIDENT:\n{json.dumps(incident, separators=(',', ':'), sort_keys=True, default=str)}"
        )
        response = client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            response_format={
                "type": "json_schema",
                "json_schema": {"name": "apexor_threat_assessment", "schema": schema, "strict": True},
            },
        )
        content = response.choices[0].message.content
        if not content:
            raise ValueError("Groq returned an empty threat assessment")
        return ThreatAssessment.model_validate_json(content)


class ThreatAnalyst:
    """Async adapter used by the deterministic event pipeline.

    The adapter exposes only advisory analysis metadata. Its result is never
    used as an authorization or containment primitive.
    """

    def __init__(self, *, client: GroqThreatAnalyst | None = None) -> None:
        self._client = client

    @property
    def enabled(self) -> bool:
        return bool(settings.groq_api_key and settings.groq_model)

    def _get_client(self) -> GroqThreatAnalyst:
        if self._client is None:
            self._client = GroqThreatAnalyst()
        return self._client

    @staticmethod
    def _payload(detection: Detection) -> dict[str, Any]:
        event = detection.event
        return {
            "event_type": event.event_type.value,
            "actor_id": event.actor_id,
            "target_id": event.target_id,
            "protected_target": event.protected_target,
            "audit_log_id": event.audit_log_id,
            "deterministic_risk_score": detection.signal.score,
            "deterministic_reason": detection.signal.reason,
            "velocity_count": detection.velocity_count,
            "velocity_window_seconds": detection.velocity_window_seconds,
            "permission_added": event.permission_added,
            "permission_removed": event.permission_removed,
        }

    async def analyze(self, detection: Detection) -> tuple[ThreatAssessment, str, float] | None:
        if not self.enabled:
            return None
        payload = self._payload(detection)
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        input_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        started = monotonic()
        assessment = await self._get_client().assess(payload)
        if assessment is None:
            return None
        return assessment, input_hash, (monotonic() - started) * 1000
