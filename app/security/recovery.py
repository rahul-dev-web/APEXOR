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
    """Reconstruct recoverable Discord state from APEXOR snapshots.

    Recovery creates new Discord resources; it cannot resurrect deleted IDs or
    message history. Dependency reconstruction keeps a mapping from original
    snapshot IDs to newly-created Discord IDs so recreated categories and roles
    can be referenced by subsequent channel/overwrite creation.

    Role membership is restored as part of role recovery. Missing/deleted users
    are ignored, while unexpected Discord/API failures are surfaced as a
    verification failure rather than falsely marking the resource protected.

    Retryable Discord failures are deliberately re-raised after their durable
    recovery action is marked FAILED. RecoveryOrchestrator owns retry/backoff;
    swallowing those exceptions here would make its retry policy ineffective.
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
        reason: str = "APEXOR security recovery",
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
            restored_ids: dict[int, int] = {}
            membership_error: str | None = None
            if resource_type == "ROLE":
                restored = await self._restore_role(guild, payload, restored_ids)
                membership_error = await self._restore_role_members(
                    guild, restored, payload.get("member_ids", [])
                )
            elif resource_type == "CHANNEL":
                await self._restore_channel_dependencies(
                    session, guild, payload, restored_ids
                )
                restored = await self._restore_channel(guild, payload, restored_ids)
            else:
                raise ValueError(f"Unsupported recovery resource type: {resource_type}")

            restored_ids[resource_id] = restored.id
            action.restored_resource_id = restored.id
            verification_error = self._verify_restored_resource(
                restored,
                resource_type=resource_type,
                snapshot=payload,
                restored_ids=restored_ids,
            )
            if verification_error is None:
                verification_error = membership_error

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
        except discord.RateLimited as exc:
            await self._mark_failed_action(session, action, str(exc))
            logger.warning(
                "Retryable Discord rate limit during recovery: guild=%s resource=%s/%s retry_after=%.2fs",
                guild.id,
                resource_type,
                resource_id,
                float(exc.retry_after),
            )
            raise
        except discord.HTTPException as exc:
            await self._mark_failed_action(session, action, str(exc))
            if 500 <= exc.status < 600:
                logger.warning(
                    "Retryable Discord %sxx error during recovery: guild=%s resource=%s/%s status=%s",
                    str(exc.status)[0],
                    guild.id,
                    resource_type,
                    resource_id,
                    exc.status,
                )
                raise
            logger.exception(
                "Recovery failed with non-retryable Discord HTTP error: guild=%s resource=%s/%s status=%s",
                guild.id,
                resource_type,
                resource_id,
                exc.status,
            )
            return action
        except (discord.Forbidden, ValueError, TypeError) as exc:
            await self._mark_failed_action(session, action, str(exc))
            logger.exception(
                "Recovery failed: guild=%s resource=%s/%s",
                guild.id,
                resource_type,
                resource_id,
            )
            return action

    @staticmethod
    async def _mark_failed_action(
        session: AsyncSession,
        action: RecoveryAction,
        error: str,
    ) -> None:
        action.status = "FAILED"
        action.error = error
        action.completed_at = datetime.now(timezone.utc)
        await session.commit()

    @staticmethod
    def _verify_restored_resource(
        restored: discord.abc.GuildChannel | discord.Role,
        *,
        resource_type: str,
        snapshot: dict[str, Any],
        restored_ids: dict[int, int] | None = None,
    ) -> str | None:
        """Verify reconstructed state against immutable snapshot invariants."""
        restored_ids = restored_ids or {}
        expected_name = snapshot.get("name")
        if expected_name is not None and getattr(restored, "name", None) != expected_name:
            return f"name mismatch: expected={expected_name!r} actual={getattr(restored, 'name', None)!r}"

        if resource_type == "ROLE":
            if not isinstance(restored, discord.Role):
                return "restored object is not a Discord role"
            if restored.managed:
                return "managed Discord roles cannot be reconstructed by APEXOR"
            expected_permissions = int(snapshot.get("permissions", 0))
            if restored.permissions.value != expected_permissions:
                return f"permission mismatch: expected={expected_permissions} actual={restored.permissions.value}"
            if bool(snapshot.get("hoist", False)) != restored.hoist:
                return f"hoist mismatch: expected={bool(snapshot.get('hoist', False))} actual={restored.hoist}"
            if bool(snapshot.get("mentionable", False)) != restored.mentionable:
                return f"mentionable mismatch: expected={bool(snapshot.get('mentionable', False))} actual={restored.mentionable}"
            return None

        if not isinstance(restored, discord.abc.GuildChannel):
            return "restored object is not a guild channel"
        expected_type = snapshot.get("type")
        if expected_type is not None and restored.type.value != int(expected_type):
            return f"channel type mismatch: expected={expected_type} actual={restored.type.value}"
        expected_parent = snapshot.get("parent_id")
        actual_parent = getattr(restored, "category_id", None)
        mapped_parent = restored_ids.get(int(expected_parent)) if expected_parent is not None else None
        if expected_parent is not None and actual_parent not in {int(expected_parent), mapped_parent}:
            parent = getattr(restored, "category", None)
            if parent is None or getattr(parent, "name", None) != snapshot.get("parent_name"):
                return f"parent mismatch: expected={expected_parent} actual={actual_parent}"
        return None

    async def _restore_role_members(
        self,
        guild: discord.Guild,
        role: discord.Role,
        member_ids: list[int] | list[str],
    ) -> str | None:
        """Reapply a role to every still-existing member from the snapshot.

        A user that no longer exists in the guild is not a recovery failure.
        API errors are failures because silently skipping them would make the
        security dashboard report an incomplete reconstruction as verified.
        """
        if role.managed:
            return "managed Discord roles cannot have membership restored"

        failed: list[str] = []
        expected_ids = {int(member_id) for member_id in member_ids}
        for member_id in sorted(expected_ids):
            member = guild.get_member(member_id)
            if member is None:
                try:
                    member = await guild.fetch_member(member_id)
                except discord.NotFound:
                    # The account/member no longer exists in this guild.
                    continue
                except discord.HTTPException as exc:
                    failed.append(f"{member_id}:{exc}")
                    continue

            if role in member.roles:
                continue
            try:
                await member.add_roles(role, reason="APEXOR role membership recovery")
            except discord.NotFound:
                continue
            except (discord.Forbidden, discord.HTTPException) as exc:
                failed.append(f"{member_id}:{exc}")

        if failed:
            return f"role membership restoration failed for {len(failed)} member(s): " + "; ".join(failed[:5])
        return None

    async def _restore_channel_dependencies(
        self,
        session: AsyncSession,
        guild: discord.Guild,
        data: dict[str, Any],
        restored_ids: dict[int, int],
    ) -> None:
        """Restore category and role dependencies before creating a channel."""
        parent_id = data.get("parent_id")
        if parent_id:
            original_parent_id = int(parent_id)
            mapped_parent_id = restored_ids.get(original_parent_id)
            parent = guild.get_channel(mapped_parent_id or original_parent_id)
            if not isinstance(parent, discord.CategoryChannel):
                parent_snapshot = await self.snapshots.latest_resource(
                    session,
                    guild_id=guild.id,
                    resource_type="CHANNEL",
                    resource_id=original_parent_id,
                )
                if parent_snapshot is not None:
                    parent_data = self.snapshots.decode(parent_snapshot)
                    if int(parent_data.get("type", -1)) == discord.ChannelType.category.value:
                        await self._restore_channel_dependencies(
                            session, guild, parent_data, restored_ids
                        )
                        parent = await self._restore_channel(
                            guild, parent_data, restored_ids
                        )
                        restored_ids[original_parent_id] = parent.id

        for item in data.get("overwrites", []):
            if item.get("target_type") != "role":
                continue
            original_role_id = int(item["target_id"])
            mapped_role_id = restored_ids.get(original_role_id)
            if guild.get_role(mapped_role_id or original_role_id) is not None:
                continue
            role_snapshot = await self.snapshots.latest_resource(
                session,
                guild_id=guild.id,
                resource_type="ROLE",
                resource_id=original_role_id,
            )
            if role_snapshot is not None:
                role = await self._restore_role(
                    guild, self.snapshots.decode(role_snapshot), restored_ids
                )
                restored_ids[original_role_id] = role.id

    async def _restore_role(
        self,
        guild: discord.Guild,
        data: dict[str, Any],
        restored_ids: dict[int, int] | None = None,
    ) -> discord.Role:
        restored_ids = restored_ids if restored_ids is not None else {}
        original_id = int(data.get("id", 0)) if data.get("id") else None
        mapped_id = restored_ids.get(original_id) if original_id else None
        if mapped_id:
            existing_mapped = guild.get_role(mapped_id)
            if existing_mapped is not None:
                return existing_mapped

        if bool(data.get("managed", False)):
            raise ValueError("Managed Discord roles cannot be recreated by APEXOR")

        existing = discord.utils.get(guild.roles, name=data["name"])
        if existing is not None and not existing.is_default() and not existing.managed:
            if original_id:
                restored_ids[original_id] = existing.id
            return existing

        role = await guild.create_role(
            name=data["name"],
            permissions=discord.Permissions(data.get("permissions", 0)),
            colour=discord.Colour(data.get("colour", 0)),
            hoist=bool(data.get("hoist", False)),
            mentionable=bool(data.get("mentionable", False)),
            reason="APEXOR snapshot recovery",
        )
        if original_id:
            restored_ids[original_id] = role.id
        position = max(1, int(data.get("position", 1)))
        try:
            await guild.edit_role_positions(
                positions={role: position}, reason="APEXOR snapshot recovery"
            )
        except discord.HTTPException:
            logger.warning(
                "Could not restore role position: guild=%s role=%s", guild.id, role.id
            )
        return role

    async def _restore_channel(
        self,
        guild: discord.Guild,
        data: dict[str, Any],
        restored_ids: dict[int, int] | None = None,
    ) -> discord.abc.GuildChannel:
        restored_ids = restored_ids if restored_ids is not None else {}
        original_id = int(data.get("id", 0)) if data.get("id") else None
        mapped_id = restored_ids.get(original_id) if original_id else None
        if mapped_id:
            mapped = guild.get_channel(mapped_id)
            if mapped is not None:
                return mapped

        name = data["name"]
        parent_id = data.get("parent_id")
        mapped_parent_id = restored_ids.get(int(parent_id)) if parent_id else None
        parent = guild.get_channel(mapped_parent_id or parent_id) if parent_id else None
        existing = next(
            (
                channel
                for channel in guild.channels
                if channel.name == name and channel.type.value == data.get("type")
            ),
            None,
        )
        if existing is not None:
            if parent is not None and existing.category_id != getattr(parent, "id", None):
                try:
                    await existing.edit(
                        category=parent, reason="APEXOR snapshot recovery"
                    )
                except discord.HTTPException:
                    logger.warning(
                        "Could not restore channel parent: guild=%s channel=%s",
                        guild.id,
                        existing.id,
                    )
            if original_id:
                restored_ids[original_id] = existing.id
            return existing

        overwrites = self._resolve_overwrites(
            guild, data.get("overwrites", []), restored_ids
        )
        channel_type = int(data.get("type", discord.ChannelType.text.value))
        reason = "APEXOR snapshot recovery"

        if channel_type == discord.ChannelType.category.value:
            channel = await guild.create_category(
                name, overwrites=overwrites, reason=reason
            )
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

        if original_id:
            restored_ids[original_id] = channel.id
        try:
            await channel.edit(
                position=max(0, int(data.get("position", 0))), reason=reason
            )
        except discord.HTTPException:
            logger.warning(
                "Could not restore channel position: guild=%s channel=%s",
                guild.id,
                channel.id,
            )
        return channel

    @staticmethod
    def _resolve_overwrites(
        guild: discord.Guild,
        items: list[dict],
        restored_ids: dict[int, int] | None = None,
    ) -> dict[discord.abc.Snowflake, discord.PermissionOverwrite]:
        restored_ids = restored_ids or {}
        resolved: dict[discord.abc.Snowflake, discord.PermissionOverwrite] = {}
        for item in items:
            original_id = int(item["target_id"])
            target_id = restored_ids.get(original_id, original_id)
            target = (
                guild.get_role(target_id)
                if item.get("target_type") == "role"
                else guild.get_member(target_id)
            )
            if target is None:
                continue
            allow = discord.Permissions(int(item.get("allow", 0)))
            deny = discord.Permissions(int(item.get("deny", 0)))
            resolved[target] = discord.PermissionOverwrite.from_pair(allow, deny)
        return resolved
