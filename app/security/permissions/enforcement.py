from dataclasses import dataclass

import discord

from app.security.permissions.policy import DEFAULT_PERMISSION_POLICY, PermissionPolicy


@dataclass(frozen=True, slots=True)
class EnforcementAction:
    role_id: int
    role_name: str
    status: str
    removed_permissions: tuple[str, ...] = ()
    reason: str = ""


class PermissionEnforcement:
    """Safely removes APEXOR-prohibited permissions from manageable roles."""

    def __init__(self, policy: PermissionPolicy = DEFAULT_PERMISSION_POLICY) -> None:
        self.policy = policy

    def _target_permissions(self, role: discord.Role) -> discord.Permissions:
        allowed = discord.Permissions(role.permissions.value)
        for name in self.policy.critical_permissions:
            setattr(allowed, name, False)
        return allowed

    def plan_role(self, guild: discord.Guild, role: discord.Role) -> EnforcementAction:
        if role.is_default():
            return EnforcementAction(role.id, role.name, "SKIPPED", reason="@everyone is never rewritten")
        if role.managed:
            return EnforcementAction(role.id, role.name, "SKIPPED", reason="Managed/integration role")
        bot_member = guild.me
        if bot_member is None or role >= bot_member.top_role:
            return EnforcementAction(role.id, role.name, "SKIPPED", reason="Role is at or above APEXOR hierarchy")
        owner = guild.get_member(guild.owner_id) if guild.owner_id else None
        if owner is not None and role.id == owner.top_role.id:
            return EnforcementAction(role.id, role.name, "SKIPPED", reason="Guild owner's top role is never mutated")

        current = self.policy.critical_names(role.permissions)
        if not current:
            return EnforcementAction(role.id, role.name, "NOOP")
        return EnforcementAction(
            role.id,
            role.name,
            "READY",
            tuple(sorted(current)),
            "Critical Discord permissions are prohibited for non-owner operator roles",
        )

    async def enforce_role(self, guild: discord.Guild, role: discord.Role, *, reason: str) -> EnforcementAction:
        action = self.plan_role(guild, role)
        if action.status != "READY":
            return action
        try:
            await role.edit(permissions=self._target_permissions(role), reason=reason)
            return EnforcementAction(role.id, role.name, "ENFORCED", action.removed_permissions, action.reason)
        except (discord.Forbidden, discord.HTTPException) as exc:
            return EnforcementAction(role.id, role.name, "FAILED", action.removed_permissions, f"{action.reason}; {type(exc).__name__}")

    async def enforce_guild(self, guild: discord.Guild, *, reason: str = "APEXOR permission policy enforcement") -> list[EnforcementAction]:
        actions: list[EnforcementAction] = []
        for role in guild.roles:
            actions.append(await self.enforce_role(guild, role, reason=reason))
        return actions
