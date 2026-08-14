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
    """Safely removes APXOR-prohibited permissions from manageable roles.

    Enforcement is deliberately conservative: the guild owner's top role,
    @everyone, managed/integration roles, and roles at/above APXOR's highest
    role are never mutated. Discord's role hierarchy remains a hard safety
    boundary.
    """

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
        if role >= guild.me.top_role:
            return EnforcementAction(role.id, role.name, "SKIPPED", reason="Role is at or above APXOR hierarchy")
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

    async def enforce_guild(self, guild: discord.Guild, *, reason: str = "APXOR permission policy enforcement") -> list[EnforcementAction]:
        actions: list[EnforcementAction] = []
        for role in guild.roles:
            action = self.plan_role(guild, role)
            if action.status != "READY":
                actions.append(action)
                continue
            try:
                await role.edit(permissions=self._target_permissions(role), reason=reason)
                actions.append(EnforcementAction(
                    role.id,
                    role.name,
                    "ENFORCED",
                    action.removed_permissions,
                    action.reason,
                ))
            except (discord.Forbidden, discord.HTTPException) as exc:
                actions.append(EnforcementAction(
                    role.id,
                    role.name,
                    "FAILED",
                    action.removed_permissions,
                    f"{action.reason}; {type(exc).__name__}",
                ))
        return actions
