from types import SimpleNamespace

from app.security.preflight import PreflightSeverity, analyze_guild_preflight, preflight_passes


def role(role_id: int, name: str, position: int, *, managed: bool = False, default: bool = False, **permissions):
    return SimpleNamespace(
        id=role_id,
        name=name,
        position=position,
        managed=managed,
        is_default=lambda: default,
        permissions=SimpleNamespace(**permissions),
    )


def guild(*roles, bot_position: int = 10, owner_id: int = 42, bot_permissions=None):
    permissions = {
        "view_audit_log": True,
        "manage_roles": True,
        "manage_channels": True,
        "manage_webhooks": True,
    }
    if bot_permissions:
        permissions.update(bot_permissions)
    bot = SimpleNamespace(
        guild_permissions=SimpleNamespace(**permissions),
        top_role=role(999, "APEXOR", bot_position),
    )
    return SimpleNamespace(id=123, owner_id=owner_id, me=bot, roles=list(roles))


def test_clean_guild_passes():
    findings = analyze_guild_preflight(
        guild(role(1, "Member", 1), role(2, "Managed Bot", 2, managed=True))
    )

    assert preflight_passes(findings)
    assert any(f.code == "MANAGEABLE_ROLES_CLEAN" for f in findings)


def test_administrator_on_manageable_role_is_critical():
    findings = analyze_guild_preflight(
        guild(role(1, "Moderator", 5, administrator=True))
    )

    assert not preflight_passes(findings)
    finding = next(f for f in findings if f.code == "ELEVATED_MANAGEABLE_ROLE")
    assert finding.severity == PreflightSeverity.CRITICAL


def test_elevated_role_at_bot_position_is_critical():
    findings = analyze_guild_preflight(
        guild(role(1, "High Mod", 10, manage_channels=True), bot_position=10)
    )

    assert not preflight_passes(findings)
    assert any(f.code == "ELEVATED_ROLE_OUT_OF_REACH" for f in findings)


def test_missing_bot_permission_fails_preflight():
    findings = analyze_guild_preflight(
        guild(role(1, "Member", 1), bot_permissions={"view_audit_log": False})
    )

    assert not preflight_passes(findings)
    finding = next(f for f in findings if f.code == "BOT_PERMISSIONS_MISSING")
    assert "view_audit_log" in finding.message


def test_managed_role_is_not_reported_as_manageable_threat():
    findings = analyze_guild_preflight(
        guild(role(1, "Integration", 9, managed=True, administrator=True))
    )

    assert preflight_passes(findings)
    assert not any(f.code == "ELEVATED_MANAGEABLE_ROLE" for f in findings)
