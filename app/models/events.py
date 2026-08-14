from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class SecurityEventLog(Base):
    """Durable record of a normalized Discord security event."""

    __tablename__ = "security_event_logs"
    __table_args__ = (
        UniqueConstraint("guild_id", "fingerprint", name="uq_security_event_logs_guild_fingerprint"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    guild_id: Mapped[int] = mapped_column(ForeignKey("guilds.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(255), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    actor_discord_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True, index=True)
    target_discord_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True, index=True)
    audit_log_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True, index=True)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    velocity_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    velocity_window_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="OBSERVED", index=True)
    action_taken: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class SecurityIncident(Base):
    """Durable incident grouping for high-risk security events."""

    __tablename__ = "security_incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_key: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    guild_id: Mapped[int] = mapped_column(ForeignKey("guilds.id", ondelete="CASCADE"), index=True)
    actor_discord_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True, index=True)
    incident_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="OPEN", index=True)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
