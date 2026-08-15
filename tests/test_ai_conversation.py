from types import SimpleNamespace

import pytest

from app.ai.conversation import ConversationalSecurityAnalyst, _compact_context
from app.core.config import settings


class _FakeCompletions:
    def create(self, **kwargs):
        assert kwargs["temperature"] == 0
        assert kwargs["max_completion_tokens"] == 700
        assert "Discord tools" in kwargs["messages"][0]["content"]
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="The latest incident is high risk."))]
        )


class _FakeClient:
    def __init__(self):
        self.chat = SimpleNamespace(completions=_FakeCompletions())


@pytest.mark.asyncio
async def test_conversation_uses_bounded_advisory_prompt(monkeypatch):
    monkeypatch.setattr(settings, "groq_api_key", "test-key")
    monkeypatch.setattr(settings, "groq_model", "test-model")

    analyst = ConversationalSecurityAnalyst()
    analyst._client = _FakeClient()

    answer = await analyst.ask(
        guild_id=1,
        user_id=2,
        question="Why is the server flagged?",
        context={
            "protection_state": "HIGH_RISK",
            "protection_score": 82,
            "secret": "must-not-be-forwarded",
        },
    )

    assert answer == "The latest incident is high risk."
    assert analyst.check_cooldown(guild_id=1, user_id=2) > 0


@pytest.mark.asyncio
async def test_conversation_rejects_overlong_question(monkeypatch):
    monkeypatch.setattr(settings, "groq_api_key", "test-key")
    monkeypatch.setattr(settings, "groq_model", "test-model")

    analyst = ConversationalSecurityAnalyst()

    with pytest.raises(ValueError, match="too long"):
        await analyst.ask(
            guild_id=1,
            user_id=2,
            question="x" * 1001,
            context={},
        )


def test_compact_context_allows_only_security_context_fields():
    rendered = _compact_context(
        {
            "protection_state": "PROTECTED",
            "protection_score": 0,
            "latest_incident": {"severity": "LOW"},
            "secret": "never-send-this",
        }
    )

    assert "PROTECTED" in rendered
    assert "never-send-this" not in rendered
