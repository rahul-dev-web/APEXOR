from __future__ import annotations

import logging

import discord
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.security import SecurityChannel

logger = logging.getLogger(__name__)


class SecurityNotifier:
    """Deliver bounded security alerts to APXOR's protected channels and owner."""

    async def notify(
        self,
        session: AsyncSession,
        guild: discord.Guild,
        *,
        severity: str,
        event_type: str,
        actor_id: int | None,
        target_id: int | None,
        risk_score: int,
        reason: str,
        owner_dm_enabled: bool = True,
        notification_enabled: bool = True,
    ) -> None:
        if not notification_enabled:
            return

        message = self._message(
            severity=severity,
            event_type=event_type,
            actor_id=actor_id,
            target_id=target_id,
            risk_score=risk_score,
            reason=reason,
        )

        critical_channel = await session.scalar(
            select(SecurityChannel).where(
                SecurityChannel.guild_id == guild.id,
                SecurityChannel.channel_type == "CRITICAL",
                SecurityChannel.is_protected.is_(True),
            )
        )
        if critical_channel is not None:
            channel = guild.get_channel(critical_channel.discord_channel_id)
            if isinstance(channel, discord.TextChannel):
                try:
                    await channel.send(message, allowed_mentions=discord.AllowedMentions.none())
                except discord.HTTPException:
                    logger.exception("Failed to send security alert to critical channel: guild=%s", guild.id)

        if owner_dm_enabled and guild.owner is not None and severity in {"CRITICAL", "EMERGENCY"}:
            try:
                await guild.owner.send(message, allowed_mentions=discord.AllowedMentions.none())
            except discord.HTTPException:
                logger.warning("Owner DM unavailable for security alert: guild=%s owner=%s", guild.id, guild.owner_id)

    @staticmethod
    def _message(
        *,
        severity: str,
        event_type: str,
        actor_id: int | None,
        target_id: int | None,
        risk_score: int,
        reason: str,
    ) -> str:
        return (
            f"🚨 **APXOR {severity} SECURITY ALERT**\n"
            f"Event: `{event_type}`\n"
            f"Actor: `{actor_id or 'unknown'}`\n"
            f"Target: `{target_id or 'unknown'}`\n"
            f"Risk: **{risk_score}/100**\n"
            f"Reason: `{reason}`\n"
            f"Action: APXOR deterministic security pipeline engaged."
        )
