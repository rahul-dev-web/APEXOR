from app.security.persistence import severity_for


def test_severity_for_uses_expected_boundaries() -> None:
    assert severity_for(0) == "INFO"
    assert severity_for(20) == "LOW"
    assert severity_for(40) == "MEDIUM"
    assert severity_for(60) == "HIGH"
    assert severity_for(80) == "CRITICAL"
    assert severity_for(95) == "EMERGENCY"


def test_severity_for_accepts_custom_thresholds() -> None:
    assert severity_for(50, high=50, critical=70, emergency=90) == "HIGH"
    assert severity_for(70, high=50, critical=70, emergency=90) == "CRITICAL"
