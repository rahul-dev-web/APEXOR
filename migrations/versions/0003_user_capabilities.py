"""Add guild-scoped APXOR capability grants.

Revision ID: 0003_user_capabilities
Revises: 0002_security_events_incidents
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003_user_capabilities"
down_revision: Union[str, Sequence[str], None] = "0002_security_events_incidents"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "user_capabilities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("guild_id", sa.Integer(), sa.ForeignKey("guilds.id", ondelete="CASCADE"), nullable=False),
        sa.Column("discord_user_id", sa.BigInteger(), nullable=False),
        sa.Column("capability", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("granted_by_discord_id", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint(
            "guild_id",
            "discord_user_id",
            "capability",
            name="uq_user_capabilities_guild_user_capability",
        ),
    )
    op.create_index("ix_user_capabilities_guild_id", "user_capabilities", ["guild_id"])
    op.create_index("ix_user_capabilities_discord_user_id", "user_capabilities", ["discord_user_id"])
    op.create_index("ix_user_capabilities_capability", "user_capabilities", ["capability"])


def downgrade() -> None:
    op.drop_index("ix_user_capabilities_capability", table_name="user_capabilities")
    op.drop_index("ix_user_capabilities_discord_user_id", table_name="user_capabilities")
    op.drop_index("ix_user_capabilities_guild_id", table_name="user_capabilities")
    op.drop_table("user_capabilities")
