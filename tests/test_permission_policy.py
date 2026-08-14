import discord

from app.security.permissions.policy import DEFAULT_PERMISSION_POLICY


def test_critical_permissions_are_separate_from_high_risk_permissions():
    permissions = discord.Permissions.none()
    permissions.administrator = True
    permissions.ban_members = True

    assert DEFAULT_PERMISSION_POLICY.critical_names(permissions) == {"administrator"}
    assert DEFAULT_PERMISSION_POLICY.permission_names(permissions) == {"administrator", "ban_members"}


def test_safe_permissions_are_not_flagged():
    permissions = discord.Permissions.none()
    permissions.view_channel = True
    permissions.send_messages = True

    assert DEFAULT_PERMISSION_POLICY.permission_names(permissions) == set()
