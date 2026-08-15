from __future__ import annotations

import argparse
import asyncio
import sys

import discord

from app.core.config import settings


REQUIRED_PERMISSIONS = (
    "view_channel",
    "send_messages",
    "embed_links",
    "read_message_history",
    "view_audit_log",
    "manage_channels",
    "manage_roles",
    "manage_webhooks",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read-only APEXOR Discord deployment preflight check."
    )
    parser.add_argument(
        "--guild-id",
        type=int,
        required=True,
        help="Disposable/test Discord guild ID to inspect.",
    )
    return parser.parse_args()


async def run(guild_id: int) -> int:
    if not settings.discord_token:
        print("FAIL: DISCORD_TOKEN is not configured.")
        return 2

    intents = discord.Intents.none()
    intents.guilds = True
    client = discord.Client(intents=intents)

    try:
        await client.login(settings.discord_token)
        guild = await client.fetch_guild(guild_id)
        await guild.fetch_roles()

        # fetch_guild does not populate a complete member cache. Fetching the
        # bot member is read-only and gives us the effective guild permissions.
        app_info = await client.application_info()
        bot_user_id = app_info.user.id
        bot_member = await guild.fetch_member(bot_user_id)

        print(f"Guild: {guild.name} ({guild.id})")
        print(f"Bot:   {app_info.user} ({bot_user_id})")
        print(f"Owner: {guild.owner_id}")
        print(f"Bot top role: {bot_member.top_role.name} ({bot_member.top_role.position})")

        failures: list[str] = []
        for permission_name in REQUIRED_PERMISSIONS:
            enabled = getattr(bot_member.guild_permissions, permission_name, False)
            print(f"permission.{permission_name}: {'OK' if enabled else 'MISSING'}")
            if not enabled:
                failures.append(permission_name)

        if bot_member.top_role.is_default():
            failures.append("bot_role_hierarchy")
            print("role_hierarchy: FAIL (bot is still at @everyone)")
        else:
            print("role_hierarchy: OK")

        # The owner is intentionally outside APEXOR's enforcement boundary.
        # This check only confirms that the bot can see the owner role and does
        # not attempt to modify any Discord resource.
        owner_member = await guild.fetch_member(guild.owner_id)
        print(f"owner_top_role: {owner_member.top_role.name} ({owner_member.top_role.position})")
        if bot_member.top_role >= owner_member.top_role:
            print("owner_hierarchy: FAIL (bot must remain below the owner role)")
            failures.append("owner_hierarchy")
        else:
            print("owner_hierarchy: OK")

        if failures:
            print("\nPREFLIGHT: FAIL")
            print("Blocking checks:")
            for failure in failures:
                print(f"- {failure}")
            return 1

        print("\nPREFLIGHT: PASS")
        print("No Discord resources were modified by this check.")
        return 0
    except (discord.HTTPException, discord.Forbidden, discord.NotFound) as exc:
        print(f"PREFLIGHT: FAIL ({type(exc).__name__}: {exc})")
        return 1
    finally:
        await client.close()


def main() -> int:
    args = parse_args()
    return asyncio.run(run(args.guild_id))


if __name__ == "__main__":
    sys.exit(main())
