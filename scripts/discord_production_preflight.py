"""Run a read-only live Discord production preflight.

This script connects to Discord, inspects the bot's cached guild state, and
reports permission/hierarchy risks without changing any Discord resource.
It is intentionally separate from the long-running Gateway worker so it can
be used as an operator-controlled deployment verification step.
"""

from __future__ import annotations

import asyncio
import os
import sys
from dataclasses import dataclass

import discord


REQUIRED_BOT_PERMISSIONS = (
    "view_channel",
    "send_messages",
    "embed_links",
    "read_message_history",
    "view_audit_log",
    "manage_channels",
    "manage_roles",
    "manage_webhooks",
)

PROTECTED_ROLE_PERMISSIONS = (
    "administrator",
    "manage_guild",
    "manage_channels",
    "manage_roles",
    "manage_webhooks",
)


@dataclass(frozen=True, slots=True)
class GuildCheck:
    guild_id: int
    guild_name: str
    owner_id: int
    bot_top_role_position: int
    bot_permissions_ok: bool
    missing_bot_permissions: tuple[str, ...]
    protected_roles: tuple[str, ...]
    hierarchy_ok: bool

    @property
    def ok(self) -> bool:
        return self.bot_permissions_ok and self.hierarchy_ok and not self.protected_roles


def _permission_names(permissions: discord.Permissions, names: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(name for name in names if not getattr(permissions, name, False))


def inspect_guild(guild: discord.Guild) -> GuildCheck:
    me = guild.me
    if me is None:
        return GuildCheck(
            guild_id=guild.id,
            guild_name=guild.name,
            owner_id=guild.owner_id,
            bot_top_role_position=-1,
            bot_permissions_ok=False,
            missing_bot_permissions=REQUIRED_BOT_PERMISSIONS,
            protected_roles=(),
            hierarchy_ok=False,
        )

    missing = _permission_names(me.guild_permissions, REQUIRED_BOT_PERMISSIONS)
    bot_top_position = me.top_role.position

    protected_roles: list[str] = []
    hierarchy_ok = bot_top_position > 0
    for role in guild.roles:
        if role.is_default() or role.managed:
            continue
        if role.position >= bot_top_position:
            continue
        if role.permissions.administrator or any(
            getattr(role.permissions, name, False) for name in PROTECTED_ROLE_PERMISSIONS[1:]
        ):
            protected_roles.append(role.name)

    # The guild owner is intentionally outside APEXOR's control and is not
    # treated as a failure when evaluating Discord's role hierarchy.
    return GuildCheck(
        guild_id=guild.id,
        guild_name=guild.name,
        owner_id=guild.owner_id,
        bot_top_role_position=bot_top_position,
        bot_permissions_ok=not missing,
        missing_bot_permissions=missing,
        protected_roles=tuple(sorted(protected_roles)),
        hierarchy_ok=hierarchy_ok,
    )


class PreflightClient(discord.Client):
    def __init__(self) -> None:
        intents = discord.Intents.none()
        intents.guilds = True
        super().__init__(intents=intents)
        self.results: list[GuildCheck] = []
        self.exit_code = 1

    async def on_ready(self) -> None:
        self.results = [inspect_guild(guild) for guild in self.guilds]
        self.exit_code = 0 if self.results and all(result.ok for result in self.results) else 1
        await self.close()


async def run_preflight(token: str) -> tuple[int, list[GuildCheck]]:
    client = PreflightClient()
    try:
        await client.start(token)
    finally:
        if not client.is_closed():
            await client.close()
    return client.exit_code, client.results


def _print_results(results: list[GuildCheck]) -> None:
    print("APEXOR live Discord production preflight")
    print("=" * 40)
    print(f"Guilds visible to bot: {len(results)}")
    print()
    for result in results:
        status = "PASS" if result.ok else "FAIL"
        print(f"[{status}] {result.guild_name} ({result.guild_id})")
        print(f"  Bot top-role position: {result.bot_top_role_position}")
        if result.missing_bot_permissions:
            print("  Missing bot permissions: " + ", ".join(result.missing_bot_permissions))
        else:
            print("  Required bot permissions: OK")
        if result.protected_roles:
            print("  Manageable roles with protected permissions: " + ", ".join(result.protected_roles))
        else:
            print("  Manageable protected-permission roles: none")
        print(f"  Role hierarchy: {'OK' if result.hierarchy_ok else 'INVALID'}")
        print()


def main() -> int:
    token = os.getenv("DISCORD_TOKEN", "").strip()
    if not token:
        print("FAIL: DISCORD_TOKEN is not configured.")
        return 1

    try:
        exit_code, results = asyncio.run(run_preflight(token))
    except discord.LoginFailure:
        print("FAIL: Discord rejected DISCORD_TOKEN.")
        return 1
    except (discord.HTTPException, discord.GatewayNotFound, discord.ConnectionClosed) as exc:
        print(f"FAIL: Discord connectivity check failed: {exc}")
        return 1

    _print_results(results)
    if exit_code:
        print("Preflight failed: fix the reported Discord permission/hierarchy risks before production use.")
    else:
        print("Preflight passed: all visible guilds satisfy the live APEXOR baseline.")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
