from types import SimpleNamespace

import discord

from app.core.constants import SecurityEventType
from app.security.permissions.audit import PermissionAudit
from app.security.risk import combine_signals, score_event


def _role(role_id: int, name: str, permissions: discord.Permissions) -> SimpleNamespace:
    return SimpleNamespace(id=role_id, name=name, permissions=permissions)


def test_administrator_is_emergency_for_non_owner_role() -> None:
    policy_audit = PermissionAudit()
    permissions = discord.Permissions.none()
    permissions.administrator = True

    finding = policy_audit.audit_role(
        _role(123, "Compromised Moderator", permissions),
        owner_role=False,
    )

    assert finding is not None
    assert finding.severity == "EMERGENCY"
    assert finding.permissions == ("administrator",)


def test_owner_role_is_not_marked_as_emergency() -> None:
    policy_audit = PermissionAudit()
    permissions = discord.Permissions(administrator=True)

    finding = policy_audit.audit_role(
        _role(456, "Owner", permissions),
        owner_role=True,
    )

    assert finding is not None
    assert finding.severity == "INFO"


def test_protected_channel_delete_is_critical_weight() -> None:
    signal = score_event(SecurityEventType.CHANNEL_DELETE, protected_target=True)

    assert signal.score == 65
    assert "protected_target" in signal.reason


def test_risk_score_is_capped_at_100() -> None:
    signals = [
        score_event(SecurityEventType.CHANNEL_DELETE, protected_target=True),
        score_event(SecurityEventType.ROLE_DELETE, protected_target=True),
        score_event(SecurityEventType.GUILD_UPDATE, protected_target=True),
    ]

    assert combine_signals(signals) == 100
