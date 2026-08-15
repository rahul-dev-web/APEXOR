from __future__ import annotations

"""Read-only production preflight for APEXOR's Discord security boundary."""

import asyncio
import json
import logging
import sys
from dataclasses import asdict, dataclass

import discord

from app.core.config import settings
from app.security.permissions.policy import DEFAULT_PERMISSION_POLICY


REQUIRED_BOT_PERMISSIONS = (
    "view_channel",
    "send_messages",
    "embed_links",
    "read_message_history",
    "use_application_commands",
    "manage_channels",
    "manage_roles",
    "view_audit_log",
    "manage_webhooks",
)


@dataclass(frozen=True, slots=True)
class RoleFinding:
    role_id: int
    role_name: str
    position: int
    managed: bool
    owner_role: bool
    above_bot: bool
    protected_permissions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GuildPreflight:
    guild_id: int
    guild_name: str
    owner_id: int | None
    bot_user_id: int | None
    bot_role_id: int | None
    bot_role_position: int | None
    bot_permissions: dict[str, bool]
    missing_bot_permissions: tuple[str, ...]
    manageable_protected_roles: tuple[RoleFinding, ...]
    hierarchy_blocked_roles: tuple[RoleFinding, ...]
    hierarchy_valid: bool
    passed: bool
    warnings: tuple[str, ...]
    failures: tuple[str, ...]


def inspect_guild(guild: discord.Guild, bot_user_id: int | None) -> GuildPreflight:
    """Inspect one guild without making any Discord mutation."""
    me = guild.me
    bot_role = me.top_role if me is not None else None
    bot_permissions = (
        {name: bool(getattr(me.guild_permissions, name, False)) for name in REQUIRED_BOT_PERMISSIONS}
        if me is not None
        else {name: False for name in REQUIRED_BOT_PERMISSIONS}
    )
    missing = tuple(name for name, enabled in bot_permissions.items() if not enabled)

    owner_top_role_id = guild.owner.top_role.id if guild.owner is not None else None
    manageable: list[RoleFinding] = []
    hierarchy_blocked: list[RoleFinding] = []
    warnings: list[str] = []
    failures: list[str] = []

    for role in guild.roles:
        critical = DEFAULT_PERMISSION_POLICY.critical_names(role.permissions)
        if not critical or role.is_default() or role.managed:
            continue
        is_owner_role = role.id == owner_top_role_id
        above_bot = bot_role is None or role.position >= bot_role.position
        finding = RoleFinding(
            role_id=role.id,
            role_name=role.name,
            position=role.position,
            managed=role.managed,
            owner_role=is_owner_role,
            above_bot=above_bot,
            protected_permissions=tuple(sorted(critical)),
        )
        if is_owner_role:
            continue
        if above_bot:
            hierarchy_blocked.append(finding)
        else:
            manageable.append(finding)

    if me is None:
        failures.append("Bot member is not available in the guild cache.")
    elif bot_role is None:
        failures.append("APEXOR bot role is unavailable.")
    elif bot_role.is_default():
        failures.append("APEXOR is using @everyone as its highest role.")

    if missing:
        failures.append("Missing required bot permissions: " + ", ".join(missing))
    if manageable:
        failures.append(
            "Manageable non-owner roles carry protected destructive permissions: "
            + "; ".join(f"{item.role_name} ({', '.join(item.protected_permissions)})" for item in manageable)
        )
    if hierarchy_blocked:
        failures.append(
            "Non-owner roles at/above APEXOR carry protected destructive permissions: "
            + "; ".join(f"{item.role_name} ({', '.join(item.protected_permissions)})" for item in hierarchy_blocked)
        )
    if guild.owner is None:
        warnings.append("Guild owner is not present in the local cache; owner-role comparison is limited.")
    if bot_user_id is not None and guild.owner_id == bot_user_id:
        warnings.append("APEXOR bot user is the guild owner; this is an unusual ownership state.")

    hierarchy_valid = me is not None and bot_role is not None and not bot_role.is_default()
    return GuildPreflight(
        guild_id=guild.id,
        guild_name=guild.name,
        owner_id=guild.owner_id,
        bot_user_id=bot_user_id,
        bot_role_id=bot_role.id if bot_role else None,
        bot_role_position=bot_role.position if bot_role else None,
        bot_permissions=bot_permissions,
        missing_bot_permissions=missing,
        manageable_protected_roles=tuple(manageable),
        hierarchy_blocked_roles=tuple(hierarchy_blocked),
        hierarchy_valid=hierarchy_valid,
        passed=not failures,
        warnings=tuple(warnings),
        failures=tuple(failures),
    )


class PreflightClient(discord.Client):
    def __init__(self) -> None:
        intents = discord.Intents.none()
        intents.guilds = True
        super().__init__(intents=intents)
        self.report: list[GuildPreflight] = []

    async def on_ready(self) -> None:
        self.report = [inspect_guild(guild, self.user.id if self.user else None) for guild in self.guilds]
        await self.close()


async def run() -> int:
    if not settings.discord_token:
        print("DISCORD_TOKEN is not configured.", file=sys.stderr)
        return 2
    logging.getLogger("discord").setLevel(logging.WARNING)
    client = PreflightClient()
    try:
        await client.start(settings.discord_token)
    except (discord.LoginFailure, discord.HTTPException, OSError) as exc:
        print(f"Discord preflight connection failed: {exc}", file=sys.stderr)
        return 2

    report = [asdict(item) for item in client.report]
    payload = {
        "mode": "READ_ONLY",
        "mutation_performed": False,
        "guild_count": len(report),
        "passed_guilds": sum(1 for item in report if item["passed"]),
        "failed_guilds": sum(1 for item in report if not item["passed"]),
        "guilds": report,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["failed_guilds"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))