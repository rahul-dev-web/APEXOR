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
    guild_id: Mapped[int] = mapped_column(BigInteger, index=True)
    fingerprint: Mapped[str] = mapped_column(String(255), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    actor_discord_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True, index=True)
    target_discord_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True, index=True)
    audit_log_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True, index=True)
    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("security_incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    velocity_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    velocity_window_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="OBSERVED", index=True)
    action_taken: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class SecurityIncident(Base):
    """Durable incident grouping and lifecycle state for high-risk activity."""

    __tablename__ = "security_incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_key: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    guild_id: Mapped[int] = mapped_column(BigInteger, index=True)
    actor_discord_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True, index=True)
    incident_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="OPEN", index=True)
    containment_status: Mapped[str] = mapped_column(String(24), nullable=False, default="PENDING")
    recovery_status: Mapped[str] = mapped_column(String(24), nullable=False, default="NOT_STARTED")
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    recovery_expected_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    recovery_completed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    recovery_failed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    containment_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    recovery_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    recovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
