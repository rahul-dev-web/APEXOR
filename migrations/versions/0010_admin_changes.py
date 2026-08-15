"""Add durable audit records for APEXOR control-plane mutations.

Revision ID: 0010_admin_changes
Revises: 0009_recovery_batch_progress
"""

from alembic import op
import sqlalchemy as sa


revision = "0010_admin_changes"
down_revision = "0009_recovery_batch_progress"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "admin_changes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("guild_id", sa.Integer(), sa.ForeignKey("guilds.id", ondelete="CASCADE"), nullable=False),
        sa.Column("actor_discord_id", sa.BigInteger(), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target_discord_id", sa.BigInteger(), nullable=False),
        sa.Column("capability", sa.String(length=64), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_admin_changes_guild_id", "admin_changes", ["guild_id"])
    op.create_index("ix_admin_changes_actor_discord_id", "admin_changes", ["actor_discord_id"])
    op.create_index("ix_admin_changes_action", "admin_changes", ["action"])
    op.create_index("ix_admin_changes_target_discord_id", "admin_changes", ["target_discord_id"])
    op.create_index("ix_admin_changes_capability", "admin_changes", ["capability"])
    op.create_index("ix_admin_changes_created_at", "admin_changes", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_admin_changes_created_at", table_name="admin_changes")
    op.drop_index("ix_admin_changes_capability", table_name="admin_changes")
    op.drop_index("ix_admin_changes_target_discord_id", table_name="admin_changes")
    op.drop_index("ix_admin_changes_action", table_name="admin_changes")
    op.drop_index("ix_admin_changes_actor_discord_id", table_name="admin_changes")
    op.drop_index("ix_admin_changes_guild_id", table_name="admin_changes")
    op.drop_table("admin_changes")
