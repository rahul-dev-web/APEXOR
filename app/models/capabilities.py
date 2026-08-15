from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class UserCapability(Base):
    """Guild-scoped APEXOR capability grant for a Discord user."""

    __tablename__ = "user_capabilities"
    __table_args__ = (
        UniqueConstraint(
            "guild_id",
            "discord_user_id",
            "capability",
            name="uq_user_capabilities_guild_user_capability",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    guild_id: Mapped[int] = mapped_column(BigInteger, index=True)
    discord_user_id: Mapped[int] = mapped_column(BigInteger, index=True)
    capability: Mapped[str] = mapped_column(String(64), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    granted_by_discord_id: Mapped[int] = mapped_column(BigInteger)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
