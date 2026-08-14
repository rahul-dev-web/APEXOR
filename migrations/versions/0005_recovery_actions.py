"""Add auditable recovery actions.

Revision ID: 0005_recovery_actions
Revises: 0004_security_snapshots
"""

from alembic import op
import sqlalchemy as sa

revision = "0005_recovery_actions"
down_revision = "0004_security_snapshots"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "recovery_actions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("guild_id", sa.Integer(), sa.ForeignKey("guilds.id", ondelete="CASCADE"), nullable=False),
        sa.Column("resource_type", sa.String(length=32), nullable=False),
        sa.Column("original_resource_id", sa.BigInteger(), nullable=False),
        sa.Column("restored_resource_id", sa.BigInteger(), nullable=True),
        sa.Column("snapshot_id", sa.Integer(), sa.ForeignKey("security_snapshots.id", ondelete="SET NULL"), nullable=True),
        sa.Column("status", sa.String(length=24), nullable=False, server_default="STARTED"),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_recovery_actions_guild_id", "recovery_actions", ["guild_id"])
    op.create_index("ix_recovery_actions_resource_type", "recovery_actions", ["resource_type"])
    op.create_index("ix_recovery_actions_original_resource_id", "recovery_actions", ["original_resource_id"])
    op.create_index("ix_recovery_actions_restored_resource_id", "recovery_actions", ["restored_resource_id"])
    op.create_index("ix_recovery_actions_status", "recovery_actions", ["status"])


def downgrade() -> None:
    op.drop_index("ix_recovery_actions_status", table_name="recovery_actions")
    op.drop_index("ix_recovery_actions_restored_resource_id", table_name="recovery_actions")
    op.drop_index("ix_recovery_actions_original_resource_id", table_name="recovery_actions")
    op.drop_index("ix_recovery_actions_resource_type", table_name="recovery_actions")
    op.drop_index("ix_recovery_actions_guild_id", table_name="recovery_actions")
    op.drop_table("recovery_actions")
