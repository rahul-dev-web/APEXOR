from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class RecoveryAction(Base):
    """Auditable recovery attempt for a Discord resource."""

    __tablename__ = "recovery_actions"

    id: Mapped[int] = mapped_column(primary_key=True)
    guild_id: Mapped[int] = mapped_column(BigInteger, index=True)
    resource_type: Mapped[str] = mapped_column(String(32), index=True)
    original_resource_id: Mapped[int] = mapped_column(BigInteger, index=True)
    restored_resource_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True, index=True)
    snapshot_id: Mapped[int | None] = mapped_column(ForeignKey("security_snapshots.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[str] = mapped_column(String(24), index=True, default="STARTED")
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
