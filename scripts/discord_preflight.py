from __future__ import annotations

import argparse
import asyncio
import sys

import discord

from app.core.config import settings
from app.security.permissions.policy import DEFAULT_PERMISSION_POLICY


async def run_preflight(guild_id: int | None) -> int:
    """Run a strictly read-only Discord production preflight."""
    if not settings.discord_token:
        print("FAIL: DISCORD_TOKEN is not configured")
        return 2

    client = discord.Client(intents=discord.Intents.none())
    try:
        await client.login(settings.discord_token)
        if guild_id is not None:
            guilds = [await client.fetch_guild(guild_id)]
        else:
            guilds = [guild async for guild in client.fetch_guilds(limit=None)]

        overall_ok = True
        print(f"APEXOR read-only preflight: {len(guilds)} guild(s)")

        for guild in guilds:
            print(f"\n[{guild.name}] ({guild.id})")
            try:
                me = await guild.fetch_member(client.user.id)  # type: ignore[union-attr]
            except discord.HTTPException as exc:
                print(f"  FAIL  could not resolve bot member: {exc}")
                overall_ok = False
                continue

            perms = me.guild_permissions
            required = {
                "view_audit_log": perms.view_audit_log,
                "manage_roles": perms.manage_roles,
                "manage_channels": perms.manage_channels,
                "manage_webhooks": perms.manage_webhooks,
            }
            for name, enabled in required.items():
                print(f"  {'PASS' if enabled else 'FAIL'}  bot permission: {name}")
                overall_ok &= enabled

            top_role = me.top_role
            print(f"  INFO  bot top role: {top_role.name} ({top_role.id}) position={top_role.position}")
            print(f"  PASS  owner id: {guild.owner_id}")

            protected_names = set(DEFAULT_PERMISSION_POLICY.critical_permissions)
            violations = []
            for role in guild.roles:
                if role.is_default() or role.managed or role.is_bot_managed():
                    continue
                dangerous = sorted(name for name in protected_names if getattr(role.permissions, name, False))
                if not dangerous:
                    continue
                status = "UNMANAGEABLE" if role >= top_role else "MANAGEABLE"
                violations.append((role, dangerous, status))

            if not violations:
                print("  PASS  no non-managed role carries protected destructive permissions")
            else:
                for role, dangerous, status in violations:
                    print(
                        f"  FAIL  role={role.name!r} id={role.id} position={role.position} "
                        f"status={status} permissions={','.join(dangerous)}"
                    )
                overall_ok = False

            if top_role.is_default():
                print("  FAIL  APEXOR role is at @everyone level; hierarchy is unsafe")
                overall_ok = False

        print("\nRESULT:", "PASS - safe to proceed to controlled destructive testing" if overall_ok else "FAIL - do not run destructive tests")
        return 0 if overall_ok else 1
    finally:
        await client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only APEXOR Discord production preflight")
    parser.add_argument("--guild", type=int, help="Only inspect this Discord guild ID")
    args = parser.parse_args()
    try:
        return asyncio.run(run_preflight(args.guild))
    except (discord.LoginFailure, discord.HTTPException) as exc:
        print(f"FAIL: Discord connection failed: {exc}")
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
