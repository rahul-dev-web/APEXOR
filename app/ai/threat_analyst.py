from __future__ import annotations

import json
import logging
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.core.config import settings

logger = logging.getLogger(__name__)


class ThreatAssessment(BaseModel):
    """Advisory AI assessment; it cannot authorize Discord mutations."""

    model_config = ConfigDict(extra="forbid")

    classification: str = Field(pattern="^(SAFE|LOW|MEDIUM|HIGH|CRITICAL|EMERGENCY)$")
    confidence: float = Field(ge=0, le=1)
    reason: str = Field(min_length=1, max_length=1000)
    recommended_action: str = Field(pattern="^(OBSERVE|ALERT|LOCKDOWN|RECOVERY_REVIEW)$")
    notify_owner: bool


class GroqThreatAnalyst:
    """Optional Groq analyst using strict JSON-schema output.

    This service is intentionally advisory. Callers must treat deterministic
    APXOR policy/risk decisions as authoritative and must never execute an AI
    recommendation as an arbitrary Discord operation.
    """

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
        """Return a validated advisory assessment, or None when AI is unavailable.

        The Groq SDK is synchronous, so this method executes it in a worker
        thread to keep the Discord Gateway event loop responsive.
        """
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
            "You are APXOR's advisory Discord security analyst. "
            "Analyze only the supplied security incident. Do not invent events. "
            "The deterministic APXOR policy engine is authoritative. "
            "You cannot execute tools, modify Discord, or override policy. "
            "Return a concise classification and explanation.\n\n"
            f"INCIDENT:\n{json.dumps(incident, separators=(',', ':'), sort_keys=True, default=str)}"
        )
        response = client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "apxor_threat_assessment",
                    "schema": schema,
                    "strict": True,
                },
            },
        )
        content = response.choices[0].message.content
        if not content:
            raise ValueError("Groq returned an empty threat assessment")
        return ThreatAssessment.model_validate_json(content)
