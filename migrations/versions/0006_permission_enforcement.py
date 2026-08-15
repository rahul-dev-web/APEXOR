"""Add explicit permission enforcement configuration.

Revision ID: 0006_permission_enforcement
Revises: 0005_recovery_actions
"""

from alembic import op
import sqlalchemy as sa

revision = "0006_permission_enforcement"
down_revision = "0005_recovery_actions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Already present in the initial security configuration schema.
    return

    op.add_column(
        "security_configs",
        sa.Column("permission_enforcement_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    return

    op.drop_column("security_configs", "permission_enforcement_enabled")
