"""Create initial APEXOR security core tables.

Revision ID: 0001_initial_security_core
Revises:
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial_security_core"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "guilds",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("discord_guild_id", sa.BigInteger(), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("owner_discord_id", sa.BigInteger(), nullable=False),
        sa.Column("protection_state", sa.String(32), nullable=False, server_default="INITIALIZING"),
        sa.Column("protection_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("discord_guild_id", name="uq_guilds_discord_guild_id"),
    )
    op.create_index("ix_guilds_discord_guild_id", "guilds", ["discord_guild_id"], unique=True)
    op.create_index("ix_guilds_owner_discord_id", "guilds", ["owner_discord_id"])

    op.create_table(
        "security_configs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("guild_id", sa.BigInteger(), nullable=False),
        sa.Column("anti_nuke_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("auto_setup_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("auto_permission_audit_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("permission_enforcement_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("audit_correlation_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("snapshot_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("recovery_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("lockdown_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("risk_threshold_high", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("risk_threshold_critical", sa.Integer(), nullable=False, server_default="80"),
        sa.Column("risk_threshold_emergency", sa.Integer(), nullable=False, server_default="95"),
        sa.Column("channel_delete_threshold", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("role_delete_threshold", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("notification_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("owner_dm_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("guild_id", name="uq_security_configs_guild_id"),
    )

    op.create_table(
        "security_roles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("guild_id", sa.BigInteger(), nullable=False),
        sa.Column("discord_role_id", sa.BigInteger(), nullable=False),
        sa.Column("role_type", sa.String(40), nullable=False),
        sa.Column("role_name", sa.String(100), nullable=False),
        sa.Column("is_protected", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.create_index("ix_security_roles_guild_id", "security_roles", ["guild_id"])
    op.create_index("ix_security_roles_discord_role_id", "security_roles", ["discord_role_id"])

    op.create_table(
        "security_channels",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("guild_id", sa.BigInteger(), nullable=False),
        sa.Column("discord_channel_id", sa.BigInteger(), nullable=False),
        sa.Column("channel_type", sa.String(40), nullable=False),
        sa.Column("channel_name", sa.String(100), nullable=False),
        sa.Column("is_protected", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.create_index("ix_security_channels_guild_id", "security_channels", ["guild_id"])
    op.create_index("ix_security_channels_discord_channel_id", "security_channels", ["discord_channel_id"])

    op.create_table(
        "user_capabilities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("guild_id", sa.BigInteger(), nullable=False),
        sa.Column("discord_user_id", sa.BigInteger(), nullable=False),
        sa.Column("capability", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("granted_by_discord_id", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("guild_id", "discord_user_id", "capability", name="uq_user_capabilities_guild_user_capability"),
    )
    op.create_index("ix_user_capabilities_guild_id", "user_capabilities", ["guild_id"])
    op.create_index("ix_user_capabilities_discord_user_id", "user_capabilities", ["discord_user_id"])
    op.create_index("ix_user_capabilities_capability", "user_capabilities", ["capability"])

    op.create_table(
        "security_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("guild_id", sa.BigInteger(), nullable=False),
        sa.Column("snapshot_key", sa.String(160), nullable=False),
        sa.Column("resource_type", sa.String(32), nullable=False),
        sa.Column("resource_id", sa.BigInteger(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("source", sa.String(32), nullable=False, server_default="PERIODIC"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("guild_id", "snapshot_key", "version", name="uq_security_snapshots_version"),
    )
    for name, column in (
        ("ix_security_snapshots_guild_id", "guild_id"),
        ("ix_security_snapshots_snapshot_key", "snapshot_key"),
        ("ix_security_snapshots_resource_type", "resource_type"),
        ("ix_security_snapshots_resource_id", "resource_id"),
    ):
        op.create_index(name, "security_snapshots", [column])

    op.create_table(
        "security_event_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("guild_id", sa.BigInteger(), nullable=False),
        sa.Column("fingerprint", sa.String(255), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("actor_discord_id", sa.BigInteger(), nullable=True),
        sa.Column("target_discord_id", sa.BigInteger(), nullable=True),
        sa.Column("audit_log_id", sa.BigInteger(), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("velocity_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("velocity_window_seconds", sa.Integer(), nullable=False, server_default="10"),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="OBSERVED"),
        sa.Column("action_taken", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("guild_id", "fingerprint", name="uq_security_event_logs_guild_fingerprint"),
    )
    for name, column in (
        ("ix_security_event_logs_guild_id", "guild_id"),
        ("ix_security_event_logs_event_type", "event_type"),
        ("ix_security_event_logs_severity", "severity"),
        ("ix_security_event_logs_actor_discord_id", "actor_discord_id"),
        ("ix_security_event_logs_target_discord_id", "target_discord_id"),
        ("ix_security_event_logs_audit_log_id", "audit_log_id"),
        ("ix_security_event_logs_status", "status"),
    ):
        op.create_index(name, "security_event_logs", [column])

    op.create_table(
        "security_incidents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_key", sa.String(255), nullable=False),
        sa.Column("guild_id", sa.BigInteger(), nullable=False),
        sa.Column("actor_discord_id", sa.BigInteger(), nullable=True),
        sa.Column("incident_type", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="OPEN"),
        sa.Column("event_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("incident_key", name="uq_security_incidents_incident_key"),
    )
    for name, column in (
        ("ix_security_incidents_incident_key", "incident_key"),
        ("ix_security_incidents_guild_id", "guild_id"),
        ("ix_security_incidents_actor_discord_id", "actor_discord_id"),
        ("ix_security_incidents_incident_type", "incident_type"),
        ("ix_security_incidents_severity", "severity"),
        ("ix_security_incidents_status", "status"),
    ):
        op.create_index(name, "security_incidents", [column])

    op.create_table(
        "recovery_actions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("guild_id", sa.BigInteger(), nullable=False),
        sa.Column("resource_type", sa.String(32), nullable=False),
        sa.Column("original_resource_id", sa.BigInteger(), nullable=False),
        sa.Column("restored_resource_id", sa.BigInteger(), nullable=True),
        sa.Column("snapshot_id", sa.Integer(), sa.ForeignKey("security_snapshots.id", ondelete="SET NULL"), nullable=True),
        sa.Column("status", sa.String(24), nullable=False, server_default="STARTED"),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    for name, column in (
        ("ix_recovery_actions_guild_id", "guild_id"),
        ("ix_recovery_actions_resource_type", "resource_type"),
        ("ix_recovery_actions_original_resource_id", "original_resource_id"),
        ("ix_recovery_actions_restored_resource_id", "restored_resource_id"),
        ("ix_recovery_actions_status", "status"),
    ):
        op.create_index(name, "recovery_actions", [column])


def downgrade() -> None:
    op.drop_table("recovery_actions")
    op.drop_table("security_incidents")
    op.drop_table("security_event_logs")
    op.drop_table("security_snapshots")
    op.drop_table("user_capabilities")
    op.drop_table("security_channels")
    op.drop_table("security_roles")
    op.drop_table("security_configs")
    op.drop_index("ix_guilds_owner_discord_id", table_name="guilds")
    op.drop_index("ix_guilds_discord_guild_id", table_name="guilds")
    op.drop_table("guilds")
