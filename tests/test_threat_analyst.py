import pytest

from app.ai.threat_analyst import GroqThreatAnalyst, ThreatAssessment


def test_threat_assessment_rejects_unknown_values() -> None:
    assessment = ThreatAssessment(
        classification="CRITICAL",
        confidence=0.98,
        reason="Rapid destructive activity",
        recommended_action="LOCKDOWN",
        notify_owner=True,
    )

    assert assessment.classification == "CRITICAL"
    assert assessment.recommended_action == "LOCKDOWN"


def test_threat_analyst_is_unavailable_without_key() -> None:
    analyst = GroqThreatAnalyst(api_key="")
    assert analyst.available is False


@pytest.mark.asyncio
async def test_threat_analyst_does_not_call_groq_without_key() -> None:
    analyst = GroqThreatAnalyst(api_key="")
    assert await analyst.assess({"risk_score": 99}) is None
