from app.security.persistence import incident_family, severity_for


def test_incident_family_groups_channel_events() -> None:
    assert incident_family("CHANNEL_DELETE") == "CHANNEL_NUKE"
    assert incident_family("CHANNEL_UPDATE") == "CHANNEL_NUKE"


def test_incident_family_groups_role_events() -> None:
    assert incident_family("ROLE_DELETE") == "ROLE_NUKE"
    assert incident_family("ROLE_UPDATE") == "ROLE_NUKE"


def test_incident_family_groups_guild_tampering() -> None:
    assert incident_family("WEBHOOKS_UPDATE") == "GUILD_TAMPERING"
    assert incident_family("INTEGRATION_UPDATE") == "GUILD_TAMPERING"


def test_severity_boundaries_are_deterministic() -> None:
    assert severity_for(0) == "INFO"
    assert severity_for(20) == "LOW"
    assert severity_for(40) == "MEDIUM"
    assert severity_for(60) == "HIGH"
    assert severity_for(80) == "CRITICAL"
    assert severity_for(95) == "EMERGENCY"
