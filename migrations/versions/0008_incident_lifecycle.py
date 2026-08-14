"""Add durable incident lifecycle state.

Revision ID: 0008_incident_lifecycle
Revises: 0007_merge_phase_1_heads
"""

from alembic import op
import sqlalchemy as sa


revision = "0008_incident_lifecycle"
down_revision = "0007_merge_phase_1_heads"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "security_event_logs",
        sa.Column("incident_id", sa.Integer(), nullable=True),
    )
    op.create_index(
        "ix_security_event_logs_incident_id",
        "security_event_logs",
        ["incident_id"],
        unique=False,
    )
    op.create_foreign_key(
        "fk_security_event_logs_incident_id",
        "security_event_logs",
        "security_incidents",
        ["incident_id"],
        ["id"],
        ondelete="SET NULL",
    )

    op.add_column(
        "security_incidents",
        sa.Column("containment_status", sa.String(length=24), nullable=False, server_default="PENDING"),
    )
    op.add_column(
        "security_incidents",
        sa.Column("recovery_status", sa.String(length=24), nullable=False, server_default="NOT_STARTED"),
    )
    op.add_column(
        "security_incidents",
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.add_column(
        "security_incidents",
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "security_incidents",
        sa.Column("containment_started_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "security_incidents",
        sa.Column("contained_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "security_incidents",
        sa.Column("recovery_started_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "security_incidents",
        sa.Column("recovered_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("security_incidents", "recovered_at")
    op.drop_column("security_incidents", "recovery_started_at")
    op.drop_column("security_incidents", "contained_at")
    op.drop_column("security_incidents", "containment_started_at")
    op.drop_column("security_incidents", "last_event_at")
    op.drop_column("security_incidents", "updated_at")
    op.drop_column("security_incidents", "recovery_status")
    op.drop_column("security_incidents", "containment_status")

    op.drop_constraint(
        "fk_security_event_logs_incident_id",
        "security_event_logs",
        type_="foreignkey",
    )
    op.drop_index("ix_security_event_logs_incident_id", table_name="security_event_logs")
    op.drop_column("security_event_logs", "incident_id")
