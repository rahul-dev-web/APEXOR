from __future__ import annotations

import discord
from discord import app_commands
from sqlalchemy import desc, select

from app.core.constants import Capability, ProtectionState
from app.database.session import SessionLocal
from app.models.guild import Guild
from app.models.recovery import RecoveryAction
from app.models.snapshots import SecuritySnapshot
from app.security.authorization import AuthorizationService
from app.security.lockdown import LockdownEngine
from app.security.recovery import RecoveryEngine
from app.security.snapshots import SnapshotService


authorization = AuthorizationService()


async def _authorized(interaction: discord.Interaction, capability: Capability) -> bool:
    if interaction.guild is None or SessionLocal is None:
        await interaction.response.send_message("This command is unavailable here.", ephemeral=True)
        return False
    async with SessionLocal() as session:
        allowed = await authorization.is_allowed(
            session,
            guild_id=interaction.guild.id,
            discord_user_id=interaction.user.id,
            capability=capability,
        )
    if not allowed:
        await interaction.response.send_message(
            f"Access denied. Required APEXOR capability: `{capability.value}`.",
            ephemeral=True,
        )
    return allowed


class RecoveryGroup(app_commands.Group):
    """Explicit, capability-gated snapshot and recovery controls."""

    def __init__(self) -> None:
        super().__init__(name="recovery", description="APEXOR snapshot and recovery operations")
        self.snapshots = SnapshotService()
        self.recovery = RecoveryEngine()
        self.lockdown = LockdownEngine()

    @app_commands.command(name="snapshot", description="Capture the current recoverable Discord state")
    async def snapshot(self, interaction: discord.Interaction) -> None:
        if not await _authorized(interaction, Capability.SNAPSHOT_CREATE):
            return
        assert interaction.guild is not None
        if SessionLocal is None:
            await interaction.response.send_message("Database is unavailable.", ephemeral=True)
            return

        await interaction.response.defer(ephemeral=True)
        async with SessionLocal() as session:
            count = await self.snapshots.capture_guild(
                session,
                interaction.guild,
                source="COMMAND",
            )
            await session.commit()
        await interaction.followup.send(
            f"Snapshot captured successfully: `{count}` recoverable resources.",
            ephemeral=True,
        )

    @app_commands.command(name="status", description="Show recovery state and latest recovery action")
    async def status(self, interaction: discord.Interaction) -> None:
        if not await _authorized(interaction, Capability.SECURITY_VIEW):
            return
        assert interaction.guild is not None
        if SessionLocal is None:
            await interaction.response.send_message("Database is unavailable.", ephemeral=True)
            return

        async with SessionLocal() as session:
            guild = await session.scalar(
                select(Guild).where(Guild.discord_guild_id == interaction.guild.id)
            )
            latest = await session.scalar(
                select(RecoveryAction)
                .where(RecoveryAction.guild_id == interaction.guild.id)
                .order_by(desc(RecoveryAction.created_at))
            )

        if guild is None:
            await interaction.response.send_message("APEXOR has not initialized this server yet.", ephemeral=True)
            return

        embed = discord.Embed(title="APEXOR Recovery", color=discord.Color.blurple())
        embed.add_field(name="Protection state", value=guild.protection_state, inline=True)
        embed.add_field(name="Risk", value=f"{guild.protection_score}/100", inline=True)
        if latest is None:
            embed.add_field(name="Latest action", value="No recovery action recorded.", inline=False)
        else:
            embed.add_field(name="Latest resource", value=f"{latest.resource_type}/{latest.original_resource_id}", inline=True)
            embed.add_field(name="Status", value=latest.status, inline=True)
            embed.add_field(name="Restored ID", value=str(latest.restored_resource_id or "—"), inline=True)
            if latest.error:
                embed.add_field(name="Error", value=latest.error[:1024], inline=False)
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @app_commands.command(name="restore", description="Restore a deleted channel or role from its latest snapshot")
    @app_commands.describe(
        resource_type="Resource type to restore",
        resource_id="Original Discord ID of the deleted resource",
        confirm="Explicit confirmation is required",
    )
    @app_commands.choices(
        resource_type=[
            app_commands.Choice(name="CHANNEL", value="CHANNEL"),
            app_commands.Choice(name="ROLE", value="ROLE"),
        ]
    )
    async def restore(
        self,
        interaction: discord.Interaction,
        resource_type: app_commands.Choice[str],
        resource_id: str,
        confirm: bool,
    ) -> None:
        if not confirm:
            await interaction.response.send_message(
                "Set `confirm` to true to start recovery.", ephemeral=True
            )
            return
        if not await _authorized(interaction, Capability.RECOVERY_MANAGE):
            return
        assert interaction.guild is not None
        if SessionLocal is None:
            await interaction.response.send_message("Database is unavailable.", ephemeral=True)
            return

        try:
            original_id = int(resource_id)
        except ValueError:
            await interaction.response.send_message("`resource_id` must be a Discord snowflake ID.", ephemeral=True)
            return
        selected_type = resource_type.value

        await interaction.response.defer(ephemeral=True)
        async with SessionLocal() as session:
            snapshot = await self.snapshots.latest_resource(
                session,
                guild_id=interaction.guild.id,
                resource_type=selected_type,
                resource_id=original_id,
            )
            if snapshot is None:
                await interaction.followup.send(
                    f"No snapshot exists for `{selected_type}/{original_id}`.", ephemeral=True
                )
                return

            guild_record = await session.scalar(
                select(Guild).where(Guild.discord_guild_id == interaction.guild.id)
            )
            if guild_record is not None:
                current_state = ProtectionState(guild_record.protection_state)
                if current_state in {ProtectionState.LOCKDOWN, ProtectionState.HIGH_RISK, ProtectionState.RECOVERY_FAILED}:
                    await self.lockdown.begin_recovery(
                        session,
                        interaction.guild.id,
                        score=max(guild_record.protection_score, 80),
                    )

            action = await self.recovery.restore_resource(
                session,
                interaction.guild,
                resource_type=selected_type,
                resource_id=original_id,
                reason=f"Manual APEXOR recovery by {interaction.user.id}",
            )

            if action.status == "VERIFIED":
                if guild_record is not None:
                    await self.lockdown.complete_recovery(session, interaction.guild.id, score=0)
                    await session.commit()
                message = f"Recovery verified: `{selected_type}/{original_id}` → `{action.restored_resource_id}`."
            else:
                if guild_record is not None:
                    await self.lockdown.mark_recovery_failed(
                        session,
                        interaction.guild.id,
                        score=max(guild_record.protection_score, 80),
                    )
                    await session.commit()
                message = f"Recovery `{action.status}` for `{selected_type}/{original_id}`: {action.error or 'unknown error'}"

        await interaction.followup.send(message[:1900], ephemeral=True)

    @app_commands.command(name="history", description="Show the latest recovery actions")
    async def history(self, interaction: discord.Interaction) -> None:
        if not await _authorized(interaction, Capability.SNAPSHOT_VIEW):
            return
        assert interaction.guild is not None
        if SessionLocal is None:
            await interaction.response.send_message("Database is unavailable.", ephemeral=True)
            return

        async with SessionLocal() as session:
            rows = (
                await session.scalars(
                    select(SecuritySnapshot)
                    .where(SecuritySnapshot.guild_id == interaction.guild.id)
                    .order_by(desc(SecuritySnapshot.created_at))
                    .limit(10)
                )
            ).all()

        if not rows:
            await interaction.response.send_message("No snapshots recorded yet.", ephemeral=True)
            return

        lines = [
            f"`{row.resource_type}/{row.resource_id}` v{row.version} • {row.source} • {row.created_at.isoformat()}"
            for row in rows
        ]
        await interaction.response.send_message(
            "**Latest APEXOR snapshots**\n" + "\n".join(lines),
            ephemeral=True,
        )
