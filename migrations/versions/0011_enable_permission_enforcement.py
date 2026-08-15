"""Enable automatic critical-permission enforcement by default.

Revision ID: 0011_enable_permission_enforcement
Revises: 0010_admin_changes
"""

from alembic import op
import sqlalchemy as sa


revision = "0011_permission_enforcement"
down_revision = "0010_admin_changes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Existing guilds were previously created with enforcement disabled. Move
    # them to the security-first default so the running bot actually enforces
    # the documented permission-isolation policy after migration.
    op.execute(
        sa.text(
            "UPDATE security_configs "
            "SET permission_enforcement_enabled = TRUE "
            "WHERE permission_enforcement_enabled = FALSE"
        )
    )


def downgrade() -> None:
    # Keep downgrade conservative: reverting the application default is enough
    # for newly-created configs; existing rows are not silently weakened.
    pass
