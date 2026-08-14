from __future__ import annotations

import logging
from datetime import datetime, timezone

import discord
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.recovery import RecoveryAction
from app.security.snapshots import SnapshotService

logger = logging.getLogger(__name__)


class RecoveryEngine:
    """Reconstruct recoverable Discord state from APXOR snapshots.

    Recovery creates new Discord resources; it cannot resurrect deleted IDs or
    message history. Every attempt is persisted for auditability.
    """

    def __init__(self) -> None:
        self.snapshots = SnapshotService()

    async def restore_resource(
        self,
        session: AsyncSession,
        guild: discord.Guild,
        *,
        resource_type: str,
        resource_id: int,
        reason: str = "APXOR security recovery",
    ) -> RecoveryAction:
        snapshot = await self.snapshots.latest_resource(
            session,
            guild_id=guild.id,
            resource_type=resource_type,
            resource_id=resource_id,
        )
        action = RecoveryAction(
            guild_id=guild.id,
            resource_type=resource_type,
            original_resource_id=resource_id,
            snapshot_id=snapshot.id if snapshot else None,
            status="STARTED",
            reason=reason,
        )
        session.add(action)
        await session.flush()

        if snapshot is None:
            action.status = "FAILED"
            action.error = "No recovery snapshot exists for this resource."
            action.completed_at = datetime.now(timezone.utc)
            await session.commit()
            return action

        try:
            payload = self.snapshots.decode(snapshot)
            if resource_type == "ROLE":
                restored = await self._restore_role(guild, payload)
            elif resource_type == "CHANNEL":
                restored = await self._restore_channel(guild, payload)
            else:
                raise ValueError(f"Unsupported recovery resource type: {resource_type}")

            action.restored_resource_id = restored.id
            action.status = "RESTORED"
            action.completed_at = datetime.now(timezone.utc)
            await session.commit()
            return action
        except (discord.Forbidden, discord.HTTPException, ValueError, TypeError) as exc:
            logger.exception("Recovery failed: guild=%s resource=%s/%s", guild.id, resource_type, resource_id)
            action.status = "FAILED"
            action.error = str(exc)
            action.completed_at = datetime.now(timezone.utc)
            await session.commit()
            return action

    async def _restore_role(self, guild: discord.Guild, data: dict) -> discord.Role:
        existing = discord.utils.get(guild.roles, name=data["name"])
        if existing is not None and not existing.is_default():
            return existing

        role = await guild.create_role(
            name=data["name"],
            permissions=discord.Permissions(data.get("permissions", 0)),
            colour=discord.Colour(data.get("colour", 0)),
            hoist=bool(data.get("hoist", False)),
            mentionable=bool(data.get("mentionable", False)),
            reason="APXOR snapshot recovery",
        )
        # Discord will clamp positions below APXOR's highest manageable role.
        position = max(1, int(data.get("position", 1)))
        try:
            await guild.edit_role_positions(positions={role: position}, reason="APXOR snapshot recovery")
        except discord.HTTPException:
            logger.warning("Could not restore role position: guild=%s role=%s", guild.id, role.id)
        return role

    async def _restore_channel(self, guild: discord.Guild, data: dict) -> discord.abc.GuildChannel:
        name = data["name"]
        parent = guild.get_channel(data.get("parent_id")) if data.get("parent_id") else None
        existing = next(
            (
                channel
                for channel in guild.channels
                if channel.name == name and channel.type.value == data.get("type")
            ),
            None,
        )
        if existing is not None:
            return existing

        overwrites = self._resolve_overwrites(guild, data.get("overwrites", []))
        channel_type = int(data.get("type", discord.ChannelType.text.value))
        reason = "APXOR snapshot recovery"

        if channel_type == discord.ChannelType.category.value:
            channel = await guild.create_category(name, overwrites=overwrites, reason=reason)
        elif channel_type == discord.ChannelType.text.value:
            channel = await guild.create_text_channel(
                name,
                category=parent if isinstance(parent, discord.CategoryChannel) else None,
                overwrites=overwrites,
                topic=data.get("topic"),
                nsfw=bool(data.get("nsfw", False)),
                slowmode_delay=int(data.get("slowmode_delay", 0)),
                reason=reason,
            )
        elif channel_type == discord.ChannelType.voice.value:
            channel = await guild.create_voice_channel(
                name,
                category=parent if isinstance(parent, discord.CategoryChannel) else None,
                overwrites=overwrites,
                bitrate=int(data.get("bitrate", 64000)),
                user_limit=int(data.get("user_limit", 0)),
                reason=reason,
            )
        elif channel_type == discord.ChannelType.stage_voice.value:
            channel = await guild.create_stage_channel(
                name,
                category=parent if isinstance(parent, discord.CategoryChannel) else None,
                overwrites=overwrites,
                bitrate=int(data.get("bitrate", 64000)),
                user_limit=int(data.get("user_limit", 0)),
                reason=reason,
            )
        else:
            raise ValueError(f"Unsupported Discord channel type for recovery: {channel_type}")

        try:
            await channel.edit(position=max(0, int(data.get("position", 0))), reason=reason)
        except discord.HTTPException:
            logger.warning("Could not restore channel position: guild=%s channel=%s", guild.id, channel.id)
        return channel

    @staticmethod
    def _resolve_overwrites(
        guild: discord.Guild,
        items: list[dict],
    ) -> dict[discord.abc.Snowflake, discord.PermissionOverwrite]:
        resolved: dict[discord.abc.Snowflake, discord.PermissionOverwrite] = {}
        for item in items:
            target_id = int(item["target_id"])
            target = guild.get_role(target_id) if item.get("target_type") == "role" else guild.get_member(target_id)
            if target is None:
                continue
            allow = discord.Permissions(int(item.get("allow", 0)))
            deny = discord.Permissions(int(item.get("deny", 0)))
            resolved[target] = discord.PermissionOverwrite.from_pair(allow, deny)
        return resolved
