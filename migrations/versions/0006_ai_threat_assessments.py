"""Add auditable Groq threat assessments.

Revision ID: 0006_ai_threat_assessments
Revises: 0005_recovery_actions
"""

from alembic import op
import sqlalchemy as sa

revision = "0006_ai_threat_assessments"
down_revision = "0005_recovery_actions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_threat_assessments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("guild_id", sa.Integer(), sa.ForeignKey("guilds.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_log_id", sa.Integer(), sa.ForeignKey("security_event_logs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("prompt_version", sa.String(length=64), nullable=False),
        sa.Column("input_hash", sa.String(length=64), nullable=False),
        sa.Column("classification", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("recommended_action", sa.String(length=16), nullable=False),
        sa.Column("notify_owner", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_ai_threat_assessments_guild_id", "ai_threat_assessments", ["guild_id"])
    op.create_index("ix_ai_threat_assessments_event_log_id", "ai_threat_assessments", ["event_log_id"])
    op.create_index("ix_ai_threat_assessments_input_hash", "ai_threat_assessments", ["input_hash"])
    op.create_index("ix_ai_threat_assessments_classification", "ai_threat_assessments", ["classification"])


def downgrade() -> None:
    op.drop_index("ix_ai_threat_assessments_classification", table_name="ai_threat_assessments")
    op.drop_index("ix_ai_threat_assessments_input_hash", table_name="ai_threat_assessments")
    op.drop_index("ix_ai_threat_assessments_event_log_id", table_name="ai_threat_assessments")
    op.drop_index("ix_ai_threat_assessments_guild_id", table_name="ai_threat_assessments")
    op.drop_table("ai_threat_assessments")
