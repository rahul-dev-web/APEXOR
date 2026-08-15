from __future__ import annotations

from datetime import timedelta

import discord
from discord import app_commands
from sqlalchemy import desc, select

from app.ai.conversation import ConversationalSecurityAnalyst
from app.ai.threat_analyst import ThreatAnalyst
from app.core.config import settings
from app.core.constants import Capability
from app.database.session import SessionLocal
from app.models.ai import AIThreatAssessment
from app.models.events import SecurityIncident
from app.models.guild import Guild
from app.models.security import SecurityChannel, SecurityConfig, SecurityRole
from app.security.authorization import AuthorizationService


authorization = AuthorizationService()
CAPABILITY_CHOICES = [app_commands.Choice(name=c.value, value=c.value) for c in Capability]


async def _authorized(interaction: discord.Interaction, capability: Capability) -> bool:
    if interaction.guild is None or SessionLocal is None or interaction.user is None:
        await interaction.response.send_message("This command is unavailable here.", ephemeral=True)
        return False
    async with SessionLocal() as session:
        allowed = await authorization.is_allowed(session, guild_id=interaction.guild.id, discord_user_id=interaction.user.id, capability=capability)
    if not allowed:
        await interaction.response.send_message(f"Access denied. Required APXOR capability: `{capability.value}`.", ephemeral=True)
    return allowed


async def _protected_resource_allowed(interaction: discord.Interaction, *, resource_type: str, resource_id: int) -> bool:
    """Protected APXOR resources require owner authority or SECURITY_MANAGE."""
    if interaction.guild is None or SessionLocal is None:
        return False
    if interaction.user.id == interaction.guild.owner_id:
        return True
    async with SessionLocal() as session:
        if resource_type == "CHANNEL":
            protected = await session.scalar(select(SecurityChannel.id).where(SecurityChannel.guild_id == interaction.guild.id, SecurityChannel.discord_channel_id == resource_id, SecurityChannel.is_protected.is_(True)))
        else:
            protected = await session.scalar(select(SecurityRole.id).where(SecurityRole.guild_id == interaction.guild.id, SecurityRole.discord_role_id == resource_id, SecurityRole.is_protected.is_(True)))
        if protected is None:
            return True
        return await authorization.is_allowed(session, guild_id=interaction.guild.id, discord_user_id=interaction.user.id, capability=Capability.SECURITY_MANAGE)


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
        await interaction.response.send_message(f"Permission enforcement **{state}**. " + ("APXOR will now remove critical permissions from manageable non-owner roles." if enabled else "Existing permissions will be audited but not automatically changed."), ephemeral=True)


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

    @app_commands.command(name="edit", description="Edit a text channel through APXOR authorization")
    @app_commands.describe(name="New channel name", topic="New topic", slowmode="Slowmode in seconds", nsfw="Whether the channel is age-restricted")
    async def edit(self, interaction: discord.Interaction, channel: discord.TextChannel, name: str | None = None, topic: str | None = None, slowmode: app_commands.Range[int, 0, 21600] | None = None, nsfw: bool | None = None) -> None:
        if not await _authorized(interaction, Capability.CHANNEL_EDIT):
            return
        if channel.guild != interaction.guild:
            await interaction.response.send_message("That channel is not in this server.", ephemeral=True)
            return
        if all(value is None for value in (name, topic, slowmode, nsfw)):
            await interaction.response.send_message("Provide at least one field to edit.", ephemeral=True)
            return
        kwargs: dict[str, object] = {}
        if name is not None:
            kwargs["name"] = name
        if topic is not None:
            kwargs["topic"] = topic
        if slowmode is not None:
            kwargs["slowmode_delay"] = slowmode
        if nsfw is not None:
            kwargs["nsfw"] = nsfw
        await channel.edit(**kwargs, reason=f"APXOR authorized by {interaction.user.id}")
        await interaction.response.send_message(f"Updated {channel.mention}.", ephemeral=True)

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
        if not await _protected_resource_allowed(interaction, resource_type="CHANNEL", resource_id=channel.id):
            await interaction.response.send_message("Protected APXOR security channels require `SECURITY_MANAGE` or owner authority.", ephemeral=True)
            return
        channel_name = channel.name
        await channel.delete(reason=f"APXOR authorized by {interaction.user.id}")
        await interaction.response.send_message(f"Deleted `#{channel_name}`.", ephemeral=True)


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

    @app_commands.command(name="edit", description="Edit a role's non-permission metadata through APXOR authorization")
    @app_commands.describe(name="New role name", hoist="Display separately", mentionable="Allow members to mention this role")
    async def edit(self, interaction: discord.Interaction, role: discord.Role, name: str | None = None, hoist: bool | None = None, mentionable: bool | None = None) -> None:
        if not await _authorized(interaction, Capability.ROLE_EDIT):
            return
        if role.guild != interaction.guild:
            await interaction.response.send_message("That role is not in this server.", ephemeral=True)
            return
        bot_member = interaction.guild.me
        if bot_member is None or role >= bot_member.top_role or role.managed or role.is_default():
            await interaction.response.send_message("APXOR cannot edit this role because of Discord hierarchy/managed-role constraints.", ephemeral=True)
            return
        if not await _protected_resource_allowed(interaction, resource_type="ROLE", resource_id=role.id):
            await interaction.response.send_message("Protected APXOR roles require `SECURITY_MANAGE` or owner authority.", ephemeral=True)
            return
        if all(value is None for value in (name, hoist, mentionable)):
            await interaction.response.send_message("Provide at least one field to edit.", ephemeral=True)
            return
        kwargs: dict[str, object] = {}
        if name is not None:
            kwargs["name"] = name
        if hoist is not None:
            kwargs["hoist"] = hoist
        if mentionable is not None:
            kwargs["mentionable"] = mentionable
        await role.edit(**kwargs, reason=f"APXOR authorized by {interaction.user.id}")
        await interaction.response.send_message(f"Updated role `{role.name}`.", ephemeral=True)

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
        if bot_member is None or role >= bot_member.top_role or role.managed or role.is_default():
            await interaction.response.send_message("APXOR cannot delete this role because of Discord hierarchy/managed-role constraints.", ephemeral=True)
            return
        if not await _protected_resource_allowed(interaction, resource_type="ROLE", resource_id=role.id):
            await interaction.response.send_message("Protected APXOR roles require `SECURITY_MANAGE` or owner authority.", ephemeral=True)
            return
        role_name = role.name
        await role.delete(reason=f"APXOR authorized by {interaction.user.id}")
        await interaction.response.send_message(f"Deleted role `{role_name}`.", ephemeral=True)


class ModerationGroup(app_commands.Group):
    def __init__(self) -> None:
        super().__init__(name="moderation", description="APXOR-authorized moderation operations")

    @app_commands.command(name="kick", description="Kick a member through APXOR authorization")
    async def kick(self, interaction: discord.Interaction, member: discord.Member, reason: str | None = None, confirm: bool = False) -> None:
        if not confirm:
            await interaction.response.send_message("Set `confirm` to true to kick the member.", ephemeral=True)
            return
        if not await _authorized(interaction, Capability.MOD_KICK):
            return
        if interaction.guild is None or member.guild != interaction.guild:
            await interaction.response.send_message("That member is not in this server.", ephemeral=True)
            return
        bot_member = interaction.guild.me
        if bot_member is None or member >= bot_member:
            await interaction.response.send_message("APXOR cannot kick a member at or above its hierarchy.", ephemeral=True)
            return
        await member.kick(reason=reason or f"APXOR authorized by {interaction.user.id}")
        await interaction.response.send_message(f"Kicked {member.mention}.", ephemeral=True)

    @app_commands.command(name="ban", description="Ban a member through APXOR authorization")
    async def ban(self, interaction: discord.Interaction, member: discord.Member, reason: str | None = None, delete_message_days: app_commands.Range[int, 0, 7] = 0, confirm: bool = False) -> None:
        if not confirm:
            await interaction.response.send_message("Set `confirm` to true to ban the member.", ephemeral=True)
            return
        if not await _authorized(interaction, Capability.MOD_BAN):
            return
        if interaction.guild is None or member.guild != interaction.guild:
            await interaction.response.send_message("That member is not in this server.", ephemeral=True)
            return
        bot_member = interaction.guild.me
        if bot_member is None or member >= bot_member:
            await interaction.response.send_message("APXOR cannot ban a member at or above its hierarchy.", ephemeral=True)
            return
        await member.ban(delete_message_days=delete_message_days, reason=reason or f"APXOR authorized by {interaction.user.id}")
        await interaction.response.send_message(f"Banned {member.mention}.", ephemeral=True)

    @app_commands.command(name="timeout", description="Timeout a member through APXOR authorization")
    @app_commands.describe(duration_minutes="Timeout duration, from 1 minute to 28 days")
    async def timeout(self, interaction: discord.Interaction, member: discord.Member, duration_minutes: app_commands.Range[int, 1, 40320], reason: str | None = None, confirm: bool = False) -> None:
        if not confirm:
            await interaction.response.send_message("Set `confirm` to true to timeout the member.", ephemeral=True)
            return
        if not await _authorized(interaction, Capability.MOD_TIMEOUT):
            return
        if interaction.guild is None or member.guild != interaction.guild:
            await interaction.response.send_message("That member is not in this server.", ephemeral=True)
            return
        bot_member = interaction.guild.me
        if bot_member is None or member >= bot_member:
            await interaction.response.send_message("APXOR cannot timeout a member at or above its hierarchy.", ephemeral=True)
            return
        await member.timeout(timedelta(minutes=duration_minutes), reason=reason or f"APXOR authorized by {interaction.user.id}")
        await interaction.response.send_message(f"Timed out {member.mention} for {duration_minutes} minute(s).", ephemeral=True)


class AIGroup(app_commands.Group):
    """Read-only AI security surfaces; AI remains advisory."""

    def __init__(self) -> None:
        super().__init__(name="ai", description="Inspect APXOR advisory AI security analysis")
        self._analyst = ThreatAnalyst()
        self._conversation = ConversationalSecurityAnalyst()

    @app_commands.command(name="status", description="Show APXOR AI availability and latest analysis")
    async def status(self, interaction: discord.Interaction) -> None:
        if not await _authorized(interaction, Capability.SECURITY_VIEW):
            return
        if interaction.guild is None or SessionLocal is None:
            await interaction.response.send_message("Database is unavailable.", ephemeral=True)
            return
        async with SessionLocal() as session:
            latest = await session.scalar(
                select(AIThreatAssessment)
                .where(AIThreatAssessment.guild_id == interaction.guild.id)
                .order_by(desc(AIThreatAssessment.created_at))
            )
        embed = discord.Embed(title="APXOR AI Security", color=discord.Color.blurple())
        embed.add_field(name="Provider", value="Groq", inline=True)
        embed.add_field(name="Runtime", value="AVAILABLE" if self._analyst.enabled else "DEGRADED", inline=True)
        embed.add_field(name="Model", value=settings.groq_model or "not configured", inline=False)
        if latest:
            embed.add_field(name="Latest classification", value=latest.classification, inline=True)
            embed.add_field(name="Confidence", value=f"{latest.confidence:.0%}", inline=True)
            embed.add_field(name="Recommendation", value=latest.recommended_action, inline=True)
            embed.add_field(name="Reason", value=latest.reason[:1024], inline=False)
        else:
            embed.add_field(name="Latest analysis", value="No persisted AI assessment yet.", inline=False)
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @app_commands.command(name="incident", description="Show the latest incident and its advisory AI assessment")
    async def incident(self, interaction: discord.Interaction) -> None:
        if not await _authorized(interaction, Capability.SECURITY_VIEW):
            return
        if interaction.guild is None or SessionLocal is None:
            await interaction.response.send_message("Database is unavailable.", ephemeral=True)
            return
        async with SessionLocal() as session:
            incident = await session.scalar(
                select(SecurityIncident)
                .where(SecurityIncident.guild_id == interaction.guild.id)
                .order_by(desc(SecurityIncident.created_at))
            )
            latest_ai = await session.scalar(
                select(AIThreatAssessment)
                .where(AIThreatAssessment.guild_id == interaction.guild.id)
                .order_by(desc(AIThreatAssessment.created_at))
            )
        if incident is None:
            await interaction.response.send_message("No security incidents have been recorded yet.", ephemeral=True)
            return
        embed = discord.Embed(title=f"APXOR Incident {incident.incident_key}", color=discord.Color.red() if incident.severity in {"CRITICAL", "EMERGENCY"} else discord.Color.orange())
        embed.add_field(name="Type", value=incident.incident_type, inline=True)
        embed.add_field(name="Severity", value=incident.severity, inline=True)
        embed.add_field(name="Risk", value=f"{incident.risk_score}/100", inline=True)
        embed.add_field(name="Status", value=incident.status, inline=True)
        embed.add_field(name="Events", value=str(incident.event_count), inline=True)
        embed.add_field(name="Actor", value=f"<@{incident.actor_discord_id}>" if incident.actor_discord_id else "Unknown", inline=True)
        embed.add_field(name="Summary", value=incident.summary[:1024], inline=False)
        if latest_ai:
            embed.add_field(name="AI classification", value=f"{latest_ai.classification} ({latest_ai.confidence:.0%})", inline=True)
            embed.add_field(name="AI recommendation", value=latest_ai.recommended_action, inline=True)
            embed.add_field(name="AI reason", value=latest_ai.reason[:1024], inline=False)
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @app_commands.command(name="ask", description="Ask the advisory APXOR security analyst a question")
    @app_commands.describe(question="Security question about the current server posture or latest incident")
    async def ask(self, interaction: discord.Interaction, question: app_commands.Range[str, 1, 1000]) -> None:
        if not await _authorized(interaction, Capability.AI_USE):
            return
        if interaction.guild is None or SessionLocal is None:
            await interaction.response.send_message("Database is unavailable.", ephemeral=True)
            return
        if not self._conversation.enabled:
            await interaction.response.send_message("APXOR AI is currently unavailable. Configure GROQ_API_KEY and GROQ_MODEL.", ephemeral=True)
            return

        await interaction.response.defer(ephemeral=True)
        async with SessionLocal() as session:
            guild = await session.scalar(select(Guild).where(Guild.discord_guild_id == interaction.guild.id))
            incident = await session.scalar(
                select(SecurityIncident)
                .where(SecurityIncident.guild_id == interaction.guild.id)
                .order_by(desc(SecurityIncident.created_at))
            )
            latest_ai = await session.scalar(
                select(AIThreatAssessment)
                .where(AIThreatAssessment.guild_id == interaction.guild.id)
                .order_by(desc(AIThreatAssessment.created_at))
            )

        if guild is None:
            await interaction.followup.send("APXOR has not initialized this server yet.", ephemeral=True)
            return

        context = {
            "protection_state": guild.protection_state,
            "protection_score": guild.protection_score,
            "latest_incident": None if incident is None else {
                "key": incident.incident_key,
                "type": incident.incident_type,
                "severity": incident.severity,
                "risk_score": incident.risk_score,
                "status": incident.status,
                "event_count": incident.event_count,
                "summary": incident.summary[:1000],
            },
            "latest_ai_assessment": None if latest_ai is None else {
                "classification": latest_ai.classification,
                "confidence": latest_ai.confidence,
                "recommendation": latest_ai.recommended_action,
                "reason": latest_ai.reason[:1000],
            },
        }

        try:
            answer = await self._conversation.ask(
                guild_id=interaction.guild.id,
                user_id=interaction.user.id,
                question=question,
                context=context,
            )
        except RuntimeError as exc:
            await interaction.followup.send(str(exc), ephemeral=True)
            return
        except Exception:
            await interaction.followup.send("APXOR AI could not complete the request. Deterministic security controls are unaffected.", ephemeral=True)
            return

        embed = discord.Embed(title="APXOR AI Analyst", description=answer, color=discord.Color.blurple())
        embed.set_footer(text="Advisory only • APXOR deterministic security policy remains authoritative")
        await interaction.followup.send(embed=embed, ephemeral=True)


class APXORCommandTree(app_commands.CommandTree):
    def __init__(self, client: discord.Client) -> None:
        super().__init__(client)
        self.add_command(SecurityGroup())
        self.add_command(ChannelGroup())
        self.add_command(RoleGroup())
        self.add_command(ModerationGroup())
        self.add_command(AIGroup())
