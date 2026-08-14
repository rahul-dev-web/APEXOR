from dataclasses import dataclass

import discord

from app.security.permissions.policy import DEFAULT_PERMISSION_POLICY, PermissionPolicy


@dataclass(frozen=True, slots=True)
class PermissionFinding:
    role_id: int
    role_name: str
    severity: str
    permissions: tuple[str, ...]
    is_owner_role: bool = False


class PermissionAudit:
    """Pure, deterministic audit of guild roles.

    This service never mutates Discord state. Detection and enforcement are
    deliberately separated so a future containment engine cannot accidentally
    change permissions while merely performing an audit.
    """

    def __init__(self, policy: PermissionPolicy = DEFAULT_PERMISSION_POLICY) -> None:
        self.policy = policy

    def audit_role(self, role: discord.Role, *, owner_role: bool = False) -> PermissionFinding | None:
        critical = self.policy.critical_names(role.permissions)
        high_risk = self.policy.permission_names(role.permissions) - critical

        if not critical and not high_risk:
            return None

        if owner_role:
            severity = "INFO"
        elif "administrator" in critical:
            severity = "EMERGENCY"
        elif critical:
            severity = "CRITICAL"
        else:
            severity = "HIGH"

        permissions = tuple(sorted(critical | high_risk))
        return PermissionFinding(
            role_id=role.id,
            role_name=role.name,
            severity=severity,
            permissions=permissions,
            is_owner_role=owner_role,
        )

    def audit_guild(self, guild: discord.Guild) -> list[PermissionFinding]:
        owner = guild.owner
        owner_role_id = owner.top_role.id if owner is not None else None

        findings: list[PermissionFinding] = []
        for role in guild.roles:
            finding = self.audit_role(role, owner_role=role.id == owner_role_id)
            if finding is not None:
                findings.append(finding)
        return findings
