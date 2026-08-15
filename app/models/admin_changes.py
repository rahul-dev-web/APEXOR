from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, JSON, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class AdminChange(Base):
    """Durable audit record for APXOR control-plane mutations."""

    __tablename__ = "admin_changes"

    id: Mapped[int] = mapped_column(primary_key=True)
    guild_id: Mapped[int] = mapped_column(
        ForeignKey("guilds.id", ondelete="CASCADE"), index=True
    )
    actor_discord_id: Mapped[int] = mapped_column(BigInteger, index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_discord_id: Mapped[int] = mapped_column(BigInteger, index=True)
    capability: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
