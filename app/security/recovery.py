from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import discord
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.recovery import RecoveryAction
from app.security.snapshots import SnapshotService

logger = logging.getLogger(__name__)


class RecoveryEngine:
    """Reconstruct recoverable Discord state from APXOR snapshots.

    Recovery creates new Discord resources; it cannot resurrect deleted IDs or
    message history. Every top-level recovery attempt is persisted for auditability.

    Dependency ordering is enforced inside the engine: roles referenced by a
    channel's permission overwrites are restored before the channel, and a
    deleted parent category is restored before its child channel.
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
                await self._restore_channel_dependencies(session, guild, payload)
                restored = await self._restore_channel(guild, payload)
            else:
                raise ValueError(f"Unsupported recovery resource type: {resource_type}")

            action.restored_resource_id = restored.id
            verification_error = self._verify_restored_resource(
                restored,
                resource_type=resource_type,
                snapshot=payload,
            )
            action.completed_at = datetime.now(timezone.utc)
            if verification_error is None:
                action.status = "VERIFIED"
                action.error = None
            else:
                action.status = "VERIFICATION_FAILED"
                action.error = verification_error
                logger.error(
                    "Recovery verification failed: guild=%s resource=%s/%s restored=%s reason=%s",
                    guild.id,
                    resource_type,
                    resource_id,
                    restored.id,
                    verification_error,
                )
            await session.commit()
            return action
        except (discord.Forbidden, discord.HTTPException, ValueError, TypeError) as exc:
            logger.exception("Recovery failed: guild=%s resource=%s/%s", guild.id, resource_type, resource_id)
            action.status = "FAILED"
            action.error = str(exc)
            action.completed_at = datetime.now(timezone.utc)
            await session.commit()
            return action

    @staticmethod
    def _verify_restored_resource(
        restored: discord.abc.GuildChannel | discord.Role,
        *,
        resource_type: str,
        snapshot: dict[str, Any],
    ) -> str | None:
        """Verify the reconstructed resource against immutable snapshot invariants.

        Discord assigns a new ID after deletion, so verification intentionally
        checks semantic state rather than the original resource ID. A recovery
        is not considered successful until the recreated object matches the
        important snapshot fields we can reliably observe after creation.
        """
        expected_name = snapshot.get("name")
        if expected_name is not None and getattr(restored, "name", None) != expected_name:
            return f"name mismatch: expected={expected_name!r} actual={getattr(restored, 'name', None)!r}"

        if resource_type == "ROLE":
            role = restored
            if not isinstance(role, discord.Role):
                return "restored object is not a Discord role"
            expected_permissions = int(snapshot.get("permissions", 0))
            if role.permissions.value != expected_permissions:
                return f"permission mismatch: expected={expected_permissions} actual={role.permissions.value}"
            if bool(snapshot.get("hoist", False)) != role.hoist:
                return f"hoist mismatch: expected={bool(snapshot.get('hoist', False))} actual={role.hoist}"
            if bool(snapshot.get("mentionable", False)) != role.mentionable:
                return f"mentionable mismatch: expected={bool(snapshot.get('mentionable', False))} actual={role.mentionable}"
            return None

        if not isinstance(restored, discord.abc.GuildChannel):
            return "restored object is not a guild channel"
        expected_type = snapshot.get("type")
        if expected_type is not None and restored.type.value != int(expected_type):
            return f"channel type mismatch: expected={expected_type} actual={restored.type.value}"
        expected_parent = snapshot.get("parent_id")
        actual_parent = getattr(restored, "category_id", None)
        if expected_parent is not None and actual_parent != int(expected_parent):
            # A deleted category is itself reconstructed with a new ID. In that
            # case the semantic parent cannot be compared to the old ID; the
            # recovery dependency step is responsible for rebuilding it.
            parent = getattr(restored, "category", None)
            if parent is None or getattr(parent, "name", None) != snapshot.get("parent_name"):
                return f"parent mismatch: expected={expected_parent} actual={actual_parent}"
        return None

    async def _restore_channel_dependencies(
        self,
        session: AsyncSession,
        guild: discord.Guild,
        data: dict[str, Any],
    ) -> None:
        """Restore resources required by a channel before creating it.

        Discord channel creation can reference a category and permission
        overwrites can reference roles. If those dependencies were deleted in
        the same nuke, creating the channel first would silently produce an
        incomplete reconstruction. We therefore restore dependencies first.
        """
        parent_id = data.get("parent_id")
        if parent_id:
            parent = guild.get_channel(int(parent_id))
            if not isinstance(parent, discord.CategoryChannel):
                parent_snapshot = await self.snapshots.latest_resource(
                    session,
                    guild_id=guild.id,
                    resource_type="CHANNEL",
                    resource_id=int(parent_id),
                )
                if parent_snapshot is not None:
                    parent_data = self.snapshots.decode(parent_snapshot)
                    if int(parent_data.get("type", -1)) == discord.ChannelType.category.value:
                        await self._restore_channel_dependencies(session, guild, parent_data)
                        await self._restore_channel(guild, parent_data)

        for item in data.get("overwrites", []):
            if item.get("target_type") != "role":
                continue
            role_id = int(item["target_id"])
            if guild.get_role(role_id) is not None:
                continue
            role_snapshot = await self.snapshots.latest_resource(
                session,
                guild_id=guild.id,
                resource_type="ROLE",
                resource_id=role_id,
            )
            if role_snapshot is not None:
                await self._restore_role(guild, self.snapshots.decode(role_snapshot))

    async def _restore_role(self, guild: discord.Guild, data: dict[str, Any]) -> discord.Role:
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
        position = max(1, int(data.get("position", 1)))
        try:
            await guild.edit_role_positions(positions={role: position}, reason="APXOR snapshot recovery")
        except discord.HTTPException:
            logger.warning("Could not restore role position: guild=%s role=%s", guild.id, role.id)
        return role

    async def _restore_channel(self, guild: discord.Guild, data: dict[str, Any]) -> discord.abc.GuildChannel:
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
            # Dependency reconciliation is still useful when a pre-existing
            # channel was found during a partial recovery.
            if parent is not None and existing.category_id != getattr(parent, "id", None):
                try:
                    await existing.edit(category=parent, reason="APXOR snapshot recovery")
                except discord.HTTPException:
                    logger.warning("Could not restore channel parent: guild=%s channel=%s", guild.id, existing.id)
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
