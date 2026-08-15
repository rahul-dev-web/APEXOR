"""Run the operator-controlled, read-only Discord production preflight.

Usage:
    python scripts/discord_preflight.py
    python scripts/discord_preflight.py --guild-id 1234567890

The command only reads guild/member/role state. It does not create, edit or
delete Discord resources and is intentionally separate from the worker.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

import discord

from app.core.config import settings
from app.security.preflight import analyze_guild_preflight, preflight_passes


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="APEXOR read-only Discord production preflight")
    parser.add_argument("--guild-id", type=int, help="Only inspect this guild")
    return parser


async def _run(guild_id: int | None) -> int:
    if not settings.discord_token:
        print("ERROR: DISCORD_TOKEN is not configured.", file=sys.stderr)
        return 2

    intents = discord.Intents.none()
    intents.guilds = True
    client = discord.Client(intents=intents)
    result_code = 0

    @client.event
    async def on_ready() -> None:
        nonlocal result_code
        guilds = [client.get_guild(guild_id)] if guild_id else list(client.guilds)
        guilds = [guild for guild in guilds if guild is not None]

        if guild_id and not guilds:
            print(f"ERROR: Guild {guild_id} is not visible to the bot.", file=sys.stderr)
            result_code = 3
        else:
            for guild in guilds:
                findings = analyze_guild_preflight(guild)
                passed = preflight_passes(findings)
                status = "PASS" if passed else "FAIL"
                print(f"\n[{status}] {guild.name} ({guild.id})")
                for finding in findings:
                    resource = f" resource={finding.resource_id}" if finding.resource_id else ""
                    print(f"  {finding.severity}: {finding.code}{resource} — {finding.message}")
                if not passed:
                    result_code = 4

        await client.close()

    try:
        await client.start(settings.discord_token)
    except discord.LoginFailure:
        print("ERROR: Discord rejected DISCORD_TOKEN.", file=sys.stderr)
        return 5
    finally:
        if not client.is_closed():
            await client.close()

    return result_code


def main() -> int:
    args = _build_parser().parse_args()
    return asyncio.run(_run(args.guild_id))


if __name__ == "__main__":
    raise SystemExit(main())
