from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from typing import Any

from app.core.config import settings

logger = logging.getLogger(__name__)


class ConversationalSecurityAnalyst:
    """Bounded, advisory-only Groq interface for operator questions.

    This surface is intentionally separate from the deterministic threat
    analyst. It has no Discord tools, no mutation authority, and no access to
    arbitrary database records. The caller supplies a small, already-authorized
    incident context.
    """

    MAX_QUESTION_LENGTH = 1000
    COOLDOWN_SECONDS = 10.0
    MAX_ANSWER_LENGTH = 1800

    def __init__(self) -> None:
        self._client: Any | None = None
        self._last_request: dict[tuple[int, int], float] = defaultdict(float)

    @property
    def enabled(self) -> bool:
        return bool(settings.groq_api_key and settings.groq_model)

    def _get_client(self) -> Any:
        if not self.enabled:
            raise RuntimeError("GROQ_API_KEY/GROQ_MODEL is not configured")
        if self._client is None:
            from groq import Groq

            self._client = Groq(api_key=settings.groq_api_key)
        return self._client

    def check_cooldown(self, *, guild_id: int, user_id: int) -> float:
        remaining = self.COOLDOWN_SECONDS - (time.monotonic() - self._last_request[(guild_id, user_id)])
        return max(0.0, remaining)

    def _mark_request(self, *, guild_id: int, user_id: int) -> None:
        self._last_request[(guild_id, user_id)] = time.monotonic()

    async def ask(self, *, guild_id: int, user_id: int, question: str, context: dict[str, Any]) -> str:
        question = question.strip()
        if not question:
            raise ValueError("Question cannot be empty.")
        if len(question) > self.MAX_QUESTION_LENGTH:
            raise ValueError(f"Question is too long; maximum is {self.MAX_QUESTION_LENGTH} characters.")
        if not self.enabled:
            raise RuntimeError("APEXOR AI is not configured.")

        remaining = self.check_cooldown(guild_id=guild_id, user_id=user_id)
        if remaining > 0:
            raise RuntimeError(f"Please wait {remaining:.1f}s before asking APEXOR AI again.")
        self._mark_request(guild_id=guild_id, user_id=user_id)

        prompt = (
            "You are APEXOR's advisory Discord security analyst. Answer the operator's "
            "question using only the supplied context. Never claim that you executed an "
            "action, changed Discord permissions, deleted/restored anything, or contacted "
            "a user. Never provide instructions that bypass APEXOR authorization or Discord "
            "permissions. If the context is insufficient, say so clearly. Keep the answer "
            "concise and operational.\n\n"
            f"SERVER SECURITY CONTEXT:\n{_compact_context(context)}\n\n"
            f"OPERATOR QUESTION:\n{question}"
        )

        try:
            response = await asyncio.to_thread(
                self._get_client().chat.completions.create,
                model=settings.groq_model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
                max_completion_tokens=700,
            )
            content = response.choices[0].message.content if response.choices else None
            if not content:
                raise RuntimeError("Groq returned an empty answer.")
            return content.strip()[: self.MAX_ANSWER_LENGTH]
        except Exception:
            logger.exception("Conversational Groq analysis failed for guild=%s user=%s", guild_id, user_id)
            raise


def _compact_context(context: dict[str, Any]) -> str:
    """Keep operator context bounded and free of secrets."""
    allowed = {
        "protection_state",
        "protection_score",
        "latest_incident",
        "latest_ai_assessment",
    }
    safe = {key: context.get(key) for key in allowed if key in context}
    return str(safe)
