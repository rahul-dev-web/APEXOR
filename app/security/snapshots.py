from __future__ import annotations

import json
import logging
from typing import Any

import discord
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.snapshots import SecuritySnapshot

logger = logging.getLogger(__name__)


class SnapshotService:
    """Persist recoverable Discord state as immutable, versioned records."""

    async def capture_guild(self, session: AsyncSession, guild: discord.Guild, *, source: str = "GUILD_SYNC") -> int:
        """Capture current guild, role and channel state in one logical snapshot pass."""
        count = 0
        await self.capture_resource(session, guild, resource_type="GUILD", source=source)
        count += 1
        for role in guild.roles:
            await self.capture_resource(session, role, resource_type="ROLE", source=source)
            count += 1
        for channel in guild.channels:
            await self.capture_resource(session, channel, resource_type="CHANNEL", source=source)
            count += 1
        await session.flush()
        return count

    async def capture_resource(
        self,
        session: AsyncSession,
        resource: Any,
        *,
        resource_type: str,
        source: str,
    ) -> SecuritySnapshot:
        guild = resource if isinstance(resource, discord.Guild) else resource.guild
        resource_id = int(resource.id)
        key = f"{resource_type.lower()}:{resource_id}"

        latest = await session.scalar(
            select(func.max(SecuritySnapshot.version)).where(
                SecuritySnapshot.guild_id == guild.id,
                SecuritySnapshot.snapshot_key == key,
            )
        )
        version = int(latest or 0) + 1
        payload = json.dumps(self._serialize(resource, resource_type), separators=(",", ":"), sort_keys=True)

        snapshot = SecuritySnapshot(
            guild_id=guild.id,
            snapshot_key=key,
            resource_type=resource_type,
            resource_id=resource_id,
            version=version,
            payload=payload,
            source=source,
        )
        session.add(snapshot)
        
        # Note: IntegrityError on duplicate version will be handled by caller
        # since multiple concurrent event handlers may attempt to capture the same version
        return snapshot

    async def latest_resource(
        self,
        session: AsyncSession,
        *,
        guild_id: int,
        resource_type: str,
        resource_id: int,
    ) -> SecuritySnapshot | None:
        key = f"{resource_type.lower()}:{resource_id}"
        return await session.scalar(
            select(SecuritySnapshot)
            .where(
                SecuritySnapshot.guild_id == guild_id,
                SecuritySnapshot.snapshot_key == key,
            )
            .order_by(SecuritySnapshot.version.desc())
            .limit(1)
        )

    @staticmethod
    def decode(snapshot: SecuritySnapshot) -> dict[str, Any]:
        return json.loads(snapshot.payload)

    @staticmethod
    def _serialize(resource: Any, resource_type: str) -> dict[str, Any]:
        if resource_type == "GUILD":
            guild: discord.Guild = resource
            return {
                "id": guild.id,
                "name": guild.name,
                "owner_id": guild.owner_id,
                "verification_level": guild.verification_level.value,
                "default_notifications": guild.default_notifications.value,
                "explicit_content_filter": guild.explicit_content_filter.value,
                "system_channel_id": guild.system_channel.id if guild.system_channel else None,
                "rules_channel_id": guild.rules_channel.id if guild.rules_channel else None,
                "public_updates_channel_id": guild.public_updates_channel.id if guild.public_updates_channel else None,
            }

        if resource_type == "ROLE":
            role: discord.Role = resource
            return {
                "id": role.id,
                "name": role.name,
                "permissions": role.permissions.value,
                "position": role.position,
                "colour": role.colour.value,
                "hoist": role.hoist,
                "mentionable": role.mentionable,
                "managed": role.managed,
                # Role membership is part of recoverable authorization state.
                # The IDs are only a snapshot; recovery verifies each member
                # still exists before attempting to reassign the role.
                "member_ids": [member.id for member in role.members],
            }

        channel: discord.abc.GuildChannel = resource
        overwrites = []
        for target, overwrite in channel.overwrites.items():
            allow, deny = overwrite.pair()
            overwrites.append(
                {
                    "target_id": target.id,
                    "target_type": "role" if isinstance(target, discord.Role) else "member",
                    "allow": allow.value,
                    "deny": deny.value,
                }
            )

        parent = channel.category
        data: dict[str, Any] = {
            "id": channel.id,
            "name": channel.name,
            "type": channel.type.value,
            "position": channel.position,
            "parent_id": channel.category_id,
            "parent_name": parent.name if parent is not None else None,
            "overwrites": overwrites,
        }
        if isinstance(channel, discord.TextChannel):
            data.update({"topic": channel.topic, "nsfw": channel.nsfw, "slowmode_delay": channel.slowmode_delay})
        elif isinstance(channel, discord.VoiceChannel):
            data.update({"bitrate": channel.bitrate, "user_limit": channel.user_limit})
        elif isinstance(channel, discord.StageChannel):
            data.update({"bitrate": channel.bitrate, "user_limit": channel.user_limit})
        return data
