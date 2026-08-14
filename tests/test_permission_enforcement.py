from unittest.mock import AsyncMock, Mock

import discord
import pytest

from app.security.permissions.enforcement import PermissionEnforcement


def make_role(role_id: int, name: str, permissions: discord.Permissions) -> Mock:
    role = Mock()
    role.id = role_id
    role.name = name
    role.permissions = permissions
    role.managed = False
    role.is_default.return_value = False
    return role


def make_guild(bot_top: Mock, owner_top_id: int = 999) -> Mock:
    guild = Mock()
    guild.me = Mock(top_role=bot_top)
    owner = Mock(top_role=Mock(id=owner_top_id))
    guild.owner_id = 1
    guild.get_member.return_value = owner
    return guild


def test_plan_skips_owner_top_role() -> None:
    bot_top = Mock()
    bot_top.__ge__ = Mock(return_value=False)
    role = make_role(999, "Owner", discord.Permissions(administrator=True))
    guild = make_guild(bot_top, owner_top_id=999)

    action = PermissionEnforcement().plan_role(guild, role)

    assert action.status == "SKIPPED"
    assert "owner" in action.reason.lower()


def test_plan_marks_manageable_admin_role_ready() -> None:
    bot_top = Mock()
    role = make_role(10, "Moderator", discord.Permissions(administrator=True))
    role.__ge__ = Mock(return_value=False)
    guild = make_guild(bot_top)

    action = PermissionEnforcement().plan_role(guild, role)

    assert action.status == "READY"
    assert "administrator" in action.removed_permissions


@pytest.mark.asyncio
async def test_enforce_role_removes_critical_permissions() -> None:
    bot_top = Mock()
    role = make_role(10, "Moderator", discord.Permissions(administrator=True, manage_channels=True))
    role.__ge__ = Mock(return_value=False)
    role.edit = AsyncMock()
    guild = make_guild(bot_top)

    action = await PermissionEnforcement().enforce_role(guild, role, reason="test")

    assert action.status == "ENFORCED"
    assert set(action.removed_permissions) == {"administrator", "manage_channels"}
    role.edit.assert_awaited_once()
    edited_permissions = role.edit.await_args.kwargs["permissions"]
    assert edited_permissions.administrator is False
    assert edited_permissions.manage_channels is False
