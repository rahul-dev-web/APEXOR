from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class SecurityConfig(Base):
    __tablename__ = "security_configs"

    id: Mapped[int] = mapped_column(primary_key=True)
    guild_id: Mapped[int] = mapped_column(BigInteger, unique=True)
    anti_nuke_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_setup_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_permission_audit_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # Security-first default: once APEXOR bootstraps a guild, manageable non-owner
    # roles must not retain the critical Discord permissions covered by the policy.
    permission_enforcement_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    audit_correlation_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    snapshot_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    recovery_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    lockdown_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    risk_threshold_high: Mapped[int] = mapped_column(Integer, default=60)
    risk_threshold_critical: Mapped[int] = mapped_column(Integer, default=80)
    risk_threshold_emergency: Mapped[int] = mapped_column(Integer, default=95)
    channel_delete_threshold: Mapped[int] = mapped_column(Integer, default=5)
    role_delete_threshold: Mapped[int] = mapped_column(Integer, default=5)
    notification_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    owner_dm_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class SecurityRole(Base):
    __tablename__ = "security_roles"

    id: Mapped[int] = mapped_column(primary_key=True)
    guild_id: Mapped[int] = mapped_column(BigInteger, index=True)
    discord_role_id: Mapped[int] = mapped_column(BigInteger, index=True)
    role_type: Mapped[str] = mapped_column(String(40))
    role_name: Mapped[str] = mapped_column(String(100))
    is_protected: Mapped[bool] = mapped_column(Boolean, default=True)


class SecurityChannel(Base):
    __tablename__ = "security_channels"

    id: Mapped[int] = mapped_column(primary_key=True)
    guild_id: Mapped[int] = mapped_column(BigInteger, index=True)
    discord_channel_id: Mapped[int] = mapped_column(BigInteger, index=True)
    channel_type: Mapped[str] = mapped_column(String(40))
    channel_name: Mapped[str] = mapped_column(String(100))
    is_protected: Mapped[bool] = mapped_column(Boolean, default=True)
