from __future__ import annotations

import discord
from discord import app_commands
from sqlalchemy import select

from app.core.constants import Capability
from app.database.session import SessionLocal
from app.models.guild import Guild
from app.models.security import SecurityConfig
from app.security.authorization import AuthorizationService


authorization = AuthorizationService()
CAPABILITY_CHOICES = [app_commands.Choice(name=c.value, value=c.value) for c in Capability]


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
        super().__init__(name="security", description="Inspect and manage APXOR security")

    @app_commands.command(name="status", description="Show APXOR protection status for this server")
    async def status(self, interaction: discord.Interaction) -> None:
        if not await _authorized(interaction, Capability.SECURITY_VIEW):
            return
        assert interaction.guild is not None
        if SessionLocal is None:
            await interaction.response.send_message("Database is unavailable.", ephemeral=True)
            return
        async with SessionLocal() as session:
            guild = await session.scalar(select(Guild).where(Guild.discord_guild_id == interaction.guild.id))
            config = await session.scalar(select(SecurityConfig).where(SecurityConfig.guild_id == interaction.guild.id))
        if guild is None:
            await interaction.response.send_message("APXOR has not initialized this server yet.", ephemeral=True)
            return
        embed = discord.Embed(title="APXOR Security", color=discord.Color.blurple())
        embed.add_field(name="Protection", value=guild.protection_state, inline=True)
        embed.add_field(name="Score", value=f"{guild.protection_score}/100", inline=True)
        embed.add_field(name="Permission Enforcement", value="ON" if config and config.permission_enforcement_enabled else "OFF", inline=True)
        embed.add_field(name="Owner", value=f"<@{guild.owner_discord_id}>", inline=True)
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @app_commands.command(name="grant", description="Grant an APXOR capability to a member")
    @app_commands.describe(member="Member receiving the capability", capability="Capability to grant")
    @app_commands.choices(capability=CAPABILITY_CHOICES)
    async def grant(self, interaction: discord.Interaction, member: discord.Member, capability: app_commands.Choice[str]) -> None:
        if not await _authorized(interaction, Capability.SECURITY_MANAGE):
            return
        assert interaction.guild is not None
        if SessionLocal is None:
            await interaction.response.send_message("Database is unavailable.", ephemeral=True)
            return
        selected = Capability(capability.value)
        async with SessionLocal() as session:
            try:
                await authorization.grant(session, guild_id=interaction.guild.id, discord_user_id=member.id, capability=selected, granted_by_discord_id=interaction.user.id)
                await session.commit()
            except (PermissionError, ValueError) as exc:
                await session.rollback()
                await interaction.response.send_message(str(exc), ephemeral=True)
                return
        await interaction.response.send_message(f"Granted `{selected.value}` to {member.mention}.", ephemeral=True)

    @app_commands.command(name="revoke", description="Revoke an APXOR capability from a member")
    @app_commands.describe(member="Member losing the capability", capability="Capability to revoke")
    @app_commands.choices(capability=CAPABILITY_CHOICES)
    async def revoke(self, interaction: discord.Interaction, member: discord.Member, capability: app_commands.Choice[str]) -> None:
        if not await _authorized(interaction, Capability.SECURITY_MANAGE):
            return
        assert interaction.guild is not None
        if SessionLocal is None:
            await interaction.response.send_message("Database is unavailable.", ephemeral=True)
            return
        selected = Capability(capability.value)
        async with SessionLocal() as session:
            try:
                changed = await authorization.revoke(session, guild_id=interaction.guild.id, discord_user_id=member.id, capability=selected, revoked_by_discord_id=interaction.user.id)
                await session.commit()
            except PermissionError as exc:
                await session.rollback()
                await interaction.response.send_message(str(exc), ephemeral=True)
                return
        message = f"Revoked `{selected.value}` from {member.mention}." if changed else "No active capability grant was found."
        await interaction.response.send_message(message, ephemeral=True)

    @app_commands.command(name="permission-enforcement", description="Enable or disable automatic removal of critical Discord permissions")
    @app_commands.describe(enabled="Whether APXOR should automatically enforce its permission policy")
    async def permission_enforcement(self, interaction: discord.Interaction, enabled: bool) -> None:
        if interaction.guild is None or interaction.user.id != interaction.guild.owner_id:
            await interaction.response.send_message("Only the current Discord guild owner can change permission enforcement.", ephemeral=True)
            return
        if SessionLocal is None:
            await interaction.response.send_message("Database is unavailable.", ephemeral=True)
            return
        async with SessionLocal() as session:
            config = await session.scalar(select(SecurityConfig).where(SecurityConfig.guild_id == interaction.guild.id))
            if config is None:
                await interaction.response.send_message("APXOR security configuration is not initialized yet.", ephemeral=True)
                return
            config.permission_enforcement_enabled = enabled
            await session.commit()
        state = "enabled" if enabled else "disabled"
        await interaction.response.send_message(
            f"Permission enforcement **{state}**. "
            + ("APXOR will now remove critical permissions from manageable non-owner roles." if enabled else "Existing permissions will be audited but not automatically changed."),
            ephemeral=True,
        )


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
        bot_member = interaction.guild.me
        if bot_member is None or role >= bot_member.top_role:
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
