from types import SimpleNamespace

import discord

from scripts.discord_production_preflight import REQUIRED_BOT_PERMISSIONS, inspect_guild


class FakeRole:
    def __init__(self, name: str, position: int, permissions: discord.Permissions, *, default: bool = False, managed: bool = False):
        self.name = name
        self.position = position
        self.permissions = permissions
        self._default = default
        self.managed = managed

    def is_default(self) -> bool:
        return self._default


def _guild(*, bot_permissions: discord.Permissions, roles: list[FakeRole], bot_position: int = 10):
    bot_role = FakeRole("APEXOR", bot_position, discord.Permissions())
    bot_member = SimpleNamespace(guild_permissions=bot_permissions, top_role=bot_role)
    return SimpleNamespace(
        id=123,
        name="Test Guild",
        owner_id=456,
        me=bot_member,
        roles=roles,
    )


def _all_required_permissions() -> discord.Permissions:
    permissions = discord.Permissions.none()
    for name in REQUIRED_BOT_PERMISSIONS:
        setattr(permissions, name, True)
    return permissions


def test_live_preflight_accepts_healthy_guild():
    guild = _guild(
        bot_permissions=_all_required_permissions(),
        roles=[FakeRole("Moderator", 5, discord.Permissions.none())],
    )

    result = inspect_guild(guild)

    assert result.ok is True
    assert result.missing_bot_permissions == ()
    assert result.protected_roles == ()
    assert result.hierarchy_risks == ()


def test_live_preflight_detects_missing_bot_permissions():
    permissions = _all_required_permissions()
    permissions.manage_roles = False
    permissions.manage_webhooks = False
    guild = _guild(bot_permissions=permissions, roles=[])

    result = inspect_guild(guild)

    assert result.ok is False
    assert result.missing_bot_permissions == ("manage_roles", "manage_webhooks")


def test_live_preflight_detects_manageable_protected_role():
    protected = discord.Permissions.none()
    protected.manage_channels = True
    guild = _guild(
        bot_permissions=_all_required_permissions(),
        roles=[FakeRole("Moderator", 5, protected)],
    )

    result = inspect_guild(guild)

    assert result.ok is False
    assert result.protected_roles == ("Moderator",)


def test_live_preflight_detects_protected_role_above_bot_hierarchy():
    protected = discord.Permissions.none()
    protected.administrator = True
    guild = _guild(
        bot_permissions=_all_required_permissions(),
        roles=[FakeRole("Legacy Admin", 12, protected)],
    )

    result = inspect_guild(guild)

    assert result.ok is False
    assert result.hierarchy_risks == ("Legacy Admin (protected permission at/above bot role)",)


def test_live_preflight_does_not_flag_managed_roles():
    protected = discord.Permissions.none()
    protected.administrator = True
    guild = _guild(
        bot_permissions=_all_required_permissions(),
        roles=[FakeRole("Integration Role", 5, protected, managed=True)],
    )

    result = inspect_guild(guild)

    assert result.ok is True
    assert result.protected_roles == ()
    assert result.hierarchy_risks == ()
