from unittest.mock import MagicMock

import discord

from app.security.recovery import RecoveryEngine


def test_role_recovery_verification_accepts_matching_state() -> None:
    role = MagicMock(spec=discord.Role)
    role.name = "Moderator"
    role.managed = False
    role.permissions = discord.Permissions(manage_messages=True)
    role.hoist = True
    role.mentionable = False

    snapshot = {
        "name": "Moderator",
        "permissions": role.permissions.value,
        "hoist": True,
        "mentionable": False,
    }

    assert RecoveryEngine._verify_restored_resource(role, resource_type="ROLE", snapshot=snapshot) is None


def test_role_recovery_verification_rejects_permission_drift() -> None:
    role = MagicMock(spec=discord.Role)
    role.name = "Moderator"
    role.managed = False
    role.permissions = discord.Permissions.none()
    role.hoist = True
    role.mentionable = False

    snapshot = {
        "name": "Moderator",
        "permissions": discord.Permissions(manage_messages=True).value,
        "hoist": True,
        "mentionable": False,
    }

    result = RecoveryEngine._verify_restored_resource(role, resource_type="ROLE", snapshot=snapshot)

    assert result is not None
    assert "permission mismatch" in result


def test_channel_recovery_verification_checks_type_and_name() -> None:
    channel = MagicMock(spec=discord.TextChannel)
    channel.name = "security"
    channel.type = discord.ChannelType.text
    channel.category_id = None

    snapshot = {"name": "security", "type": discord.ChannelType.text.value, "parent_id": None}

    assert RecoveryEngine._verify_restored_resource(channel, resource_type="CHANNEL", snapshot=snapshot) is None
