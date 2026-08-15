"""Add versioned Discord security snapshots.

Revision ID: 0004_security_snapshots
Revises: 0003_user_capabilities
"""

from alembic import op
import sqlalchemy as sa

revision = "0004_security_snapshots"
down_revision = "0003_user_capabilities"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Already created by 0001_initial_security_core.
    return

    op.create_table(
        "security_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("guild_id", sa.Integer(), sa.ForeignKey("guilds.id", ondelete="CASCADE"), nullable=False),
        sa.Column("snapshot_key", sa.String(length=160), nullable=False),
        sa.Column("resource_type", sa.String(length=32), nullable=False),
        sa.Column("resource_id", sa.BigInteger(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False, server_default="PERIODIC"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("guild_id", "snapshot_key", "version", name="uq_security_snapshots_version"),
    )
    op.create_index("ix_security_snapshots_guild_id", "security_snapshots", ["guild_id"])
    op.create_index("ix_security_snapshots_snapshot_key", "security_snapshots", ["snapshot_key"])
    op.create_index("ix_security_snapshots_resource_type", "security_snapshots", ["resource_type"])
    op.create_index("ix_security_snapshots_resource_id", "security_snapshots", ["resource_id"])


def downgrade() -> None:
    return

    op.drop_index("ix_security_snapshots_resource_id", table_name="security_snapshots")
    op.drop_index("ix_security_snapshots_resource_type", table_name="security_snapshots")
    op.drop_index("ix_security_snapshots_snapshot_key", table_name="security_snapshots")
    op.drop_index("ix_security_snapshots_guild_id", table_name="security_snapshots")
    op.drop_table("security_snapshots")
