from types import SimpleNamespace

import pytest

from app.ai.threat_analyst import ThreatAnalyst
from app.core.config import settings
from app.core.constants import SecurityEventType
from app.security.events import Detection, SecurityEvent
from app.security.risk import RiskSignal


class FakeCompletions:
    def __init__(self, content: str):
        self.content = content

    async def create(self, **kwargs):
        assert kwargs["response_format"]["type"] == "json_schema"
        assert kwargs["response_format"]["json_schema"]["strict"] is True
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=self.content))]
        )


class FakeClient:
    def __init__(self, content: str):
        self.chat = SimpleNamespace(completions=FakeCompletions(content))


def sample_detection() -> Detection:
    event = SecurityEvent(
        guild_id=123,
        event_type=SecurityEventType.CHANNEL_DELETE,
        target_id=456,
        actor_id=789,
        protected_target=True,
    )
    return Detection(
        event=event,
        signal=RiskSignal(score=95, reason="protected_channel_delete"),
        velocity_count=5,
        velocity_window_seconds=10,
    )


@pytest.mark.asyncio
async def test_structured_threat_assessment(monkeypatch):
    monkeypatch.setattr(settings, "groq_api_key", "test-key")
    monkeypatch.setattr(settings, "groq_model", "test-model")
    client = FakeClient(
        '{"classification":"EMERGENCY","confidence":0.98,'
        '"reason":"Protected channel deletion with rapid velocity",'
        '"recommended_action":"LOCKDOWN","notify_owner":true}'
    )

    result = await ThreatAnalyst(client=client).analyze(sample_detection())

    assert result is not None
    assessment, input_hash, latency_ms = result
    assert assessment.classification == "EMERGENCY"
    assert assessment.recommended_action == "LOCKDOWN"
    assert assessment.notify_owner is True
    assert len(input_hash) == 64
    assert latency_ms >= 0


@pytest.mark.asyncio
async def test_ai_disabled_when_key_is_missing(monkeypatch):
    monkeypatch.setattr(settings, "groq_api_key", "")
    monkeypatch.setattr(settings, "groq_model", "test-model")

    result = await ThreatAnalyst().analyze(sample_detection())

    assert result is None


@pytest.mark.asyncio
async def test_invalid_model_output_is_non_fatal(monkeypatch):
    monkeypatch.setattr(settings, "groq_api_key", "test-key")
    monkeypatch.setattr(settings, "groq_model", "test-model")
    client = FakeClient('{"classification":"NOT_A_VALID_LEVEL"}')

    result = await ThreatAnalyst(client=client).analyze(sample_detection())

    assert result is None
