from app.security.persistence import incident_family, severity_for


def test_severity_boundaries() -> None:
    assert severity_for(0) == "INFO"
    assert severity_for(20) == "LOW"
    assert severity_for(40) == "MEDIUM"
    assert severity_for(60) == "HIGH"
    assert severity_for(80) == "CRITICAL"
    assert severity_for(95) == "EMERGENCY"
    assert severity_for(100) == "EMERGENCY"


def test_incident_family_groups_related_events() -> None:
    assert incident_family("CHANNEL_DELETE") == "CHANNEL_NUKE"
    assert incident_family("CHANNEL_UPDATE") == "CHANNEL_NUKE"
    assert incident_family("ROLE_DELETE") == "ROLE_NUKE"
    assert incident_family("ROLE_UPDATE") == "ROLE_NUKE"
    assert incident_family("GUILD_UPDATE") == "GUILD_TAMPERING"
    assert incident_family("MEMBER_REMOVE") == "MEMBER_MODERATION"
    assert incident_family("UNKNOWN_SECURITY_EVENT") == "SECURITY_ACTIVITY"
