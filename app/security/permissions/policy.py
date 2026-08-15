from dataclasses import dataclass

import discord


@dataclass(frozen=True, slots=True)
class PermissionPolicy:
    """Security policy for permissions APEXOR treats as privileged.

    The policy is intentionally stricter than Discord's normal moderation model:
    operators should use APEXOR capabilities instead of receiving destructive
    Discord permissions directly.
    """

    critical_permissions: frozenset[str] = frozenset(
        {
            "administrator",
            "manage_guild",
            "manage_channels",
            "manage_roles",
            "manage_webhooks",
        }
    )

    high_risk_permissions: frozenset[str] = frozenset(
        {
            "ban_members",
            "kick_members",
            "moderate_members",
            "manage_nicknames",
            "manage_messages",
            "manage_threads",
        }
    )

    def permission_names(self, permissions: discord.Permissions) -> set[str]:
        return {
            name
            for name in self.critical_permissions | self.high_risk_permissions
            if getattr(permissions, name, False)
        }

    def critical_names(self, permissions: discord.Permissions) -> set[str]:
        return {
            name
            for name in self.critical_permissions
            if getattr(permissions, name, False)
        }


DEFAULT_PERMISSION_POLICY = PermissionPolicy()
