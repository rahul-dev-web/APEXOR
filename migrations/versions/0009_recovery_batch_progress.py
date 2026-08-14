"""Add durable recovery batch progress counters.

Revision ID: 0009_recovery_batch_progress
Revises: 0008_incident_lifecycle
"""

from alembic import op
import sqlalchemy as sa


revision = "0009_recovery_batch_progress"
down_revision = "0008_incident_lifecycle"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "security_incidents",
        sa.Column("recovery_expected_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "security_incidents",
        sa.Column("recovery_completed_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "security_incidents",
        sa.Column("recovery_failed_count", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("security_incidents", "recovery_failed_count")
    op.drop_column("security_incidents", "recovery_completed_count")
    op.drop_column("security_incidents", "recovery_expected_count")
