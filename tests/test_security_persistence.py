from app.security.persistence import severity_for


def test_severity_boundaries() -> None:
    assert severity_for(0) == "INFO"
    assert severity_for(20) == "LOW"
    assert severity_for(40) == "MEDIUM"
    assert severity_for(60) == "HIGH"
    assert severity_for(80) == "CRITICAL"
    assert severity_for(95) == "EMERGENCY"
    assert severity_for(100) == "EMERGENCY"
