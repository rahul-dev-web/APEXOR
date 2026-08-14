"""Add durable security events and incident records.

Revision ID: 0002_security_events_incidents
Revises: 0001_initial_security_core
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002_security_events_incidents"
down_revision: Union[str, Sequence[str], None] = "0001_initial_security_core"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "security_event_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("guild_id", sa.Integer(), sa.ForeignKey("guilds.id", ondelete="CASCADE"), nullable=False),
        sa.Column("fingerprint", sa.String(length=255), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("actor_discord_id", sa.BigInteger(), nullable=True),
        sa.Column("target_discord_id", sa.BigInteger(), nullable=True),
        sa.Column("audit_log_id", sa.BigInteger(), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("velocity_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("velocity_window_seconds", sa.Integer(), nullable=False, server_default="10"),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False, server_default="OBSERVED"),
        sa.Column("action_taken", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("guild_id", "fingerprint", name="uq_security_event_logs_guild_fingerprint"),
    )
    for name, column in (
        ("guild_id", "guild_id"),
        ("event_type", "event_type"),
        ("severity", "severity"),
        ("actor_discord_id", "actor_discord_id"),
        ("target_discord_id", "target_discord_id"),
        ("audit_log_id", "audit_log_id"),
        ("status", "status"),
    ):
        op.create_index(f"ix_security_event_logs_{name}", "security_event_logs", [column])

    op.create_table(
        "security_incidents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_key", sa.String(length=255), nullable=False),
        sa.Column("guild_id", sa.Integer(), sa.ForeignKey("guilds.id", ondelete="CASCADE"), nullable=False),
        sa.Column("actor_discord_id", sa.BigInteger(), nullable=True),
        sa.Column("incident_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False, server_default="OPEN"),
        sa.Column("event_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("incident_key", name="uq_security_incidents_incident_key"),
    )
    for name, column in (
        ("guild_id", "guild_id"),
        ("actor_discord_id", "actor_discord_id"),
        ("incident_type", "incident_type"),
        ("severity", "severity"),
        ("status", "status"),
    ):
        op.create_index(f"ix_security_incidents_{name}", "security_incidents", [column])
    op.create_index("ix_security_incidents_incident_key", "security_incidents", ["incident_key"])


def downgrade() -> None:
    op.drop_index("ix_security_incidents_incident_key", table_name="security_incidents")
    for name in ("status", "severity", "incident_type", "actor_discord_id", "guild_id"):
        op.drop_index(f"ix_security_incidents_{name}", table_name="security_incidents")
    op.drop_table("security_incidents")

    for name in ("status", "audit_log_id", "target_discord_id", "actor_discord_id", "severity", "event_type", "guild_id"):
        op.drop_index(f"ix_security_event_logs_{name}", table_name="security_event_logs")
    op.drop_table("security_event_logs")
