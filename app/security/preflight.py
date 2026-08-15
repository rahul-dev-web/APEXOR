"""Read-only Discord production preflight checks.

This module deliberately contains no Discord mutations.  It converts a live
``discord.Guild`` view into deterministic findings that an operator can review
before enabling destructive recovery/containment tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable


class PreflightSeverity(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True, slots=True)
class PreflightFinding:
    severity: PreflightSeverity
    code: str
    message: str
    guild_id: int
    resource_id: int | None = None


PROTECTED_PERMISSION_NAMES = (
    "administrator",
    "manage_guild",
    "manage_channels",
    "manage_roles",
    "manage_webhooks",
)

REQUIRED_BOT_PERMISSIONS = (
    "view_audit_log",
    "manage_roles",
    "manage_channels",
    "manage_webhooks",
)


def _has_any_protected_permission(role) -> list[str]:
    permissions = role.permissions
    return [name for name in PROTECTED_PERMISSION_NAMES if getattr(permissions, name, False)]


def analyze_guild_preflight(guild, *, required_permissions: Iterable[str] = REQUIRED_BOT_PERMISSIONS) -> list[PreflightFinding]:
    """Analyze one live guild without changing any Discord state.

    The function intentionally relies only on the guild/member/role objects
    supplied by discord.py, making it deterministic and straightforward to
    unit-test with lightweight fakes.
    """

    findings: list[PreflightFinding] = []
    guild_id = int(guild.id)
    bot_member = getattr(guild, "me", None)

    if bot_member is None:
        findings.append(
            PreflightFinding(
                PreflightSeverity.CRITICAL,
                "BOT_MEMBER_UNAVAILABLE",
                "APEXOR's guild member is unavailable; role hierarchy and bot permissions cannot be verified.",
                guild_id,
            )
        )
        return findings

    bot_permissions = bot_member.guild_permissions
    missing = [
        permission
        for permission in required_permissions
        if not getattr(bot_permissions, permission, False)
    ]
    if missing:
        findings.append(
            PreflightFinding(
                PreflightSeverity.CRITICAL,
                "BOT_PERMISSIONS_MISSING",
                "Missing required bot permissions: " + ", ".join(missing),
                guild_id,
            )
        )
    else:
        findings.append(
            PreflightFinding(
                PreflightSeverity.INFO,
                "BOT_PERMISSIONS_OK",
                "Required bot permissions are present.",
                guild_id,
            )
        )

    owner_id = getattr(guild, "owner_id", None)
    bot_top_role = getattr(bot_member, "top_role", None)
    if bot_top_role is None:
        findings.append(
            PreflightFinding(
                PreflightSeverity.CRITICAL,
                "BOT_ROLE_UNAVAILABLE",
                "APEXOR's highest role is unavailable; manageable-role verification cannot continue.",
                guild_id,
            )
        )
        return findings

    if owner_id is None:
        findings.append(
            PreflightFinding(
                PreflightSeverity.WARNING,
                "OWNER_ID_UNAVAILABLE",
                "Guild owner ID is unavailable in the current Discord state.",
                guild_id,
            )
        )

    manageable_elevated = 0
    blocked_by_hierarchy = 0

    for role in getattr(guild, "roles", ()):  # @everyone is normally included here.
        if getattr(role, "is_default", lambda: False)():
            continue
        if getattr(role, "managed", False):
            continue

        protected = _has_any_protected_permission(role)
        if not protected:
            continue

        position = int(getattr(role, "position", 0))
        bot_position = int(getattr(bot_top_role, "position", 0))

        if position >= bot_position:
            blocked_by_hierarchy += 1
            findings.append(
                PreflightFinding(
                    PreflightSeverity.CRITICAL,
                    "ELEVATED_ROLE_OUT_OF_REACH",
                    f"Role {role.name!r} carries protected permissions ({', '.join(protected)}) and is at/above APEXOR's top role.",
                    guild_id,
                    int(role.id),
                )
            )
            continue

        # The guild owner is not a role property, so this is deliberately a
        # warning rather than an attempt to infer ownership from role state.
        manageable_elevated += 1
        severity = PreflightSeverity.CRITICAL if "administrator" in protected else PreflightSeverity.WARNING
        findings.append(
            PreflightFinding(
                severity,
                "ELEVATED_MANAGEABLE_ROLE",
                f"Role {role.name!r} carries protected permissions: {', '.join(protected)}.",
                guild_id,
                int(role.id),
            )
        )

    if manageable_elevated == 0 and blocked_by_hierarchy == 0:
        findings.append(
            PreflightFinding(
                PreflightSeverity.INFO,
                "MANAGEABLE_ROLES_CLEAN",
                "No manageable non-managed roles carry protected destructive permissions.",
                guild_id,
            )
        )

    if owner_id is not None:
        findings.append(
            PreflightFinding(
                PreflightSeverity.INFO,
                "OWNER_IDENTIFIED",
                f"Guild owner ID: {owner_id}.",
                guild_id,
            )
        )

    return findings


def preflight_passes(findings: Iterable[PreflightFinding]) -> bool:
    """Return whether a guild is safe for destructive integration testing."""

    return not any(finding.severity == PreflightSeverity.CRITICAL for finding in findings)
