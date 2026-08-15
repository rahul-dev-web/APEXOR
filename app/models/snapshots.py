from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class SecuritySnapshot(Base):
    """Versioned point-in-time representation of recoverable Discord state."""

    __tablename__ = "security_snapshots"
    __table_args__ = (
        UniqueConstraint("guild_id", "snapshot_key", "version", name="uq_security_snapshots_version"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    guild_id: Mapped[int] = mapped_column(BigInteger, index=True)
    snapshot_key: Mapped[str] = mapped_column(String(160), index=True)
    resource_type: Mapped[str] = mapped_column(String(32), index=True)
    resource_id: Mapped[int] = mapped_column(BigInteger, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="PERIODIC")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
