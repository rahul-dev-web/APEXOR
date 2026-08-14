"""Create initial APXOR security core tables.

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
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("owner_discord_id", sa.BigInteger(), nullable=False),
        sa.Column("protection_state", sa.String(length=32), nullable=False, server_default="INITIALIZING"),
        sa.Column("protection_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("discord_guild_id", name="uq_guilds_discord_guild_id"),
    )
    op.create_index("ix_guilds_discord_guild_id", "guilds", ["discord_guild_id"])
    op.create_index("ix_guilds_owner_discord_id", "guilds", ["owner_discord_id"])

    op.create_table(
        "security_configs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("guild_id", sa.Integer(), sa.ForeignKey("guilds.id", ondelete="CASCADE"), nullable=False),
        sa.Column("anti_nuke_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("auto_setup_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("auto_permission_audit_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
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
        sa.Column("guild_id", sa.Integer(), sa.ForeignKey("guilds.id", ondelete="CASCADE"), nullable=False),
        sa.Column("discord_role_id", sa.BigInteger(), nullable=False),
        sa.Column("role_type", sa.String(length=40), nullable=False),
        sa.Column("role_name", sa.String(length=100), nullable=False),
        sa.Column("is_protected", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.create_index("ix_security_roles_guild_id", "security_roles", ["guild_id"])
    op.create_index("ix_security_roles_discord_role_id", "security_roles", ["discord_role_id"])

    op.create_table(
        "security_channels",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("guild_id", sa.Integer(), sa.ForeignKey("guilds.id", ondelete="CASCADE"), nullable=False),
        sa.Column("discord_channel_id", sa.BigInteger(), nullable=False),
        sa.Column("channel_type", sa.String(length=40), nullable=False),
        sa.Column("channel_name", sa.String(length=100), nullable=False),
        sa.Column("is_protected", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.create_index("ix_security_channels_guild_id", "security_channels", ["guild_id"])
    op.create_index("ix_security_channels_discord_channel_id", "security_channels", ["discord_channel_id"])


def downgrade() -> None:
    op.drop_table("security_channels")
    op.drop_table("security_roles")
    op.drop_table("security_configs")
    op.drop_index("ix_guilds_owner_discord_id", table_name="guilds")
    op.drop_index("ix_guilds_discord_guild_id", table_name="guilds")
    op.drop_table("guilds")
