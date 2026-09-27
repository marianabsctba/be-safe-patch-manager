from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from .database import Base


def utcnow():
    return datetime.now(timezone.utc)


class Agent(Base):
    __tablename__ = "agents"
    id = Column(String(36), primary_key=True)
    hostname = Column(String(255), nullable=False, index=True)
    os_family = Column(String(32), nullable=False)
    os_name = Column(String(255), nullable=False)
    os_version = Column(String(255), nullable=False, default="")
    arch = Column(String(64), nullable=False, default="")
    ip_address = Column(String(128), nullable=False, default="")
    tags = Column(Text, nullable=False, default="[]")
    token_hash = Column(String(64), nullable=False, unique=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    reboot_required = Column(Boolean, default=False, nullable=False)
    pending_updates = Column(Integer, default=0, nullable=False)
    critical_updates = Column(Integer, default=0, nullable=False)
    inventory_json = Column(Text, nullable=False, default="{}")
    patch_scan_json = Column(Text, nullable=False, default="[]")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    jobs = relationship("PatchJob", back_populates="agent", cascade="all, delete-orphan")


class Campaign(Base):
    __tablename__ = "campaigns"
    id = Column(String(36), primary_key=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False, default="")
    target_os = Column(String(32), nullable=False, default="all")
    target_tag = Column(String(128), nullable=False, default="")
    ring_percent = Column(Integer, nullable=False, default=100)
    action = Column(String(64), nullable=False, default="install_updates")
    payload_json = Column(Text, nullable=False, default="{}")
    not_before = Column(DateTime(timezone=True), nullable=True)
    allow_reboot = Column(Boolean, default=False, nullable=False)
    status = Column(String(32), nullable=False, default="draft")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    jobs = relationship("PatchJob", back_populates="campaign", cascade="all, delete-orphan")


class PatchJob(Base):
    __tablename__ = "patch_jobs"
    id = Column(String(36), primary_key=True)
    campaign_id = Column(String(36), ForeignKey("campaigns.id"), nullable=False, index=True)
    agent_id = Column(String(36), ForeignKey("agents.id"), nullable=False, index=True)
    action = Column(String(64), nullable=False)
    payload_json = Column(Text, nullable=False, default="{}")
    status = Column(String(32), nullable=False, default="pending")
    not_before = Column(DateTime(timezone=True), nullable=True)
    claimed_at = Column(DateTime(timezone=True), nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    result_json = Column(Text, nullable=False, default="{}")
    error = Column(Text, nullable=False, default="")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    campaign = relationship("Campaign", back_populates="jobs")
    agent = relationship("Agent", back_populates="jobs")


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    actor = Column(String(255), nullable=False)
    event_type = Column(String(128), nullable=False)
    object_type = Column(String(64), nullable=False, default="")
    object_id = Column(String(64), nullable=False, default="")
    details_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
