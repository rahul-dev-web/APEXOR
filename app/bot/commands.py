from __future__ import annotations

import logging

import discord
from discord import app_commands

from app.core.constants import Capability
from app.database.session import SessionLocal
from app.security.authorization import AuthorizationService

logger = logging.getLogger(__name__)
authorization = AuthorizationService()


async def _authorized(interaction: discord.Interaction, capability: Capability) -> bool:
    if interaction.guild is None or SessionLocal is None or interaction.user is None:
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
            f"Access denied. Required APXOR capability: `{capability.value}`.",
            ephemeral=True,
        )
    return allowed


class SecurityGroup(app_commands.Group):
    def __init__(self) -> None:
        super().__init__(name="security", description="Inspect APXOR security state")

    @app_commands.command(name="status", description="Show APXOR protection status for this server")
    async def status(self, interaction: discord.Interaction) -> None:
        if not await _authorized(interaction, Capability.SECURITY_VIEW):
            return
        assert interaction.guild is not None
        if SessionLocal is None:
            await interaction.response.send_message("Database is unavailable.", ephemeral=True)
            return
        async with SessionLocal() as session:
            from sqlalchemy import select
            from app.models.guild import Guild
            guild = await session.scalar(select(Guild).where(Guild.discord_guild_id == interaction.guild.id))
        if guild is None:
            await interaction.response.send_message("APXOR has not initialized this server yet.", ephemeral=True)
            return
        embed = discord.Embed(title="APXOR Security", color=discord.Color.blurple())
        embed.add_field(name="Protection", value=guild.protection_state, inline=True)
        embed.add_field(name="Score", value=f"{guild.protection_score}/100", inline=True)
        embed.add_field(name="Owner", value=f"<@{guild.owner_discord_id}>", inline=True)
        await interaction.response.send_message(embed=embed, ephemeral=True)


class ChannelGroup(app_commands.Group):
    def __init__(self) -> None:
        super().__init__(name="channel", description="APXOR-controlled channel operations")

    @app_commands.command(name="create", description="Create a text channel through APXOR authorization")
    @app_commands.describe(name="Channel name", category="Optional category")
    async def create(self, interaction: discord.Interaction, name: str, category: discord.CategoryChannel | None = None) -> None:
        if not await _authorized(interaction, Capability.CHANNEL_CREATE):
            return
        assert interaction.guild is not None
        channel = await interaction.guild.create_text_channel(name, category=category, reason=f"APXOR authorized by {interaction.user.id}")
        await interaction.response.send_message(f"Created {channel.mention}.", ephemeral=True)

    @app_commands.command(name="delete", description="Delete a channel through APXOR authorization")
    @app_commands.describe(channel="Channel to delete", confirm="Explicit confirmation is required")
    async def delete(self, interaction: discord.Interaction, channel: discord.TextChannel, confirm: bool) -> None:
        if not confirm:
            await interaction.response.send_message("Set `confirm` to true to delete the channel.", ephemeral=True)
            return
        if not await _authorized(interaction, Capability.CHANNEL_DELETE):
            return
        if channel.guild != interaction.guild:
            await interaction.response.send_message("That channel is not in this server.", ephemeral=True)
            return
        await channel.delete(reason=f"APXOR authorized by {interaction.user.id}")
        await interaction.response.send_message(f"Deleted `#{channel.name}`.", ephemeral=True)


class RoleGroup(app_commands.Group):
    def __init__(self) -> None:
        super().__init__(name="role", description="APXOR-controlled role operations")

    @app_commands.command(name="create", description="Create a role through APXOR authorization")
    @app_commands.describe(name="Role name")
    async def create(self, interaction: discord.Interaction, name: str) -> None:
        if not await _authorized(interaction, Capability.ROLE_CREATE):
            return
        assert interaction.guild is not None
        role = await interaction.guild.create_role(name=name, reason=f"APXOR authorized by {interaction.user.id}")
        await interaction.response.send_message(f"Created role `{role.name}`.", ephemeral=True)

    @app_commands.command(name="delete", description="Delete a role through APXOR authorization")
    @app_commands.describe(role="Role to delete", confirm="Explicit confirmation is required")
    async def delete(self, interaction: discord.Interaction, role: discord.Role, confirm: bool) -> None:
        if not confirm:
            await interaction.response.send_message("Set `confirm` to true to delete the role.", ephemeral=True)
            return
        if not await _authorized(interaction, Capability.ROLE_DELETE):
            return
        if role.guild != interaction.guild:
            await interaction.response.send_message("That role is not in this server.", ephemeral=True)
            return
        if interaction.guild is not None and role >= interaction.guild.me.top_role:
            await interaction.response.send_message("APXOR cannot manage a role at or above its highest role.", ephemeral=True)
            return
        await role.delete(reason=f"APXOR authorized by {interaction.user.id}")
        await interaction.response.send_message(f"Deleted role `{role.name}`.", ephemeral=True)


class APXORCommandTree(app_commands.CommandTree):
    def __init__(self, client: discord.Client) -> None:
        super().__init__(client)
        self.add_command(SecurityGroup())
        self.add_command(ChannelGroup())
        self.add_command(RoleGroup())
