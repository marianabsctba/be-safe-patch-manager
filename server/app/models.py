from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
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
    vulnerabilities = relationship("VulnerabilityFinding", back_populates="agent")


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
    claim_token_hash = Column(String(64), nullable=False, default="")
    lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    last_lease_at = Column(DateTime(timezone=True), nullable=True)
    attempt_count = Column(Integer, nullable=False, default=0)
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    result_json = Column(Text, nullable=False, default="{}")
    error = Column(Text, nullable=False, default="")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    campaign = relationship("Campaign", back_populates="jobs")
    agent = relationship("Agent", back_populates="jobs")


class VulnerabilityFinding(Base):
    __tablename__ = "vulnerability_findings"
    __table_args__ = (
        UniqueConstraint("source", "external_id", "cve", name="uq_vulnerability_source_external_cve"),
    )

    id = Column(String(36), primary_key=True)
    source = Column(String(64), nullable=False, default="openvas", index=True)
    external_id = Column(String(255), nullable=False)
    scan_id = Column(String(255), nullable=False, default="")
    agent_id = Column(String(36), ForeignKey("agents.id"), nullable=True, index=True)
    host = Column(String(255), nullable=False, default="")
    ip_address = Column(String(128), nullable=False, default="", index=True)
    cve = Column(String(64), nullable=False, default="", index=True)
    title = Column(Text, nullable=False, default="")
    severity = Column(String(32), nullable=False, default="unknown", index=True)
    cvss = Column(Float, nullable=False, default=0.0)
    port = Column(String(128), nullable=False, default="")
    solution = Column(Text, nullable=False, default="")
    patch_refs_json = Column(Text, nullable=False, default="[]")
    raw_json = Column(Text, nullable=False, default="{}")
    status = Column(String(32), nullable=False, default="open", index=True)
    first_seen = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    agent = relationship("Agent", back_populates="vulnerabilities")


class IntegrationState(Base):
    __tablename__ = "integration_states"

    name = Column(String(64), primary_key=True)
    enabled = Column(Boolean, default=False, nullable=False)
    status = Column(String(32), nullable=False, default="idle")
    last_attempt_at = Column(DateTime(timezone=True), nullable=True)
    last_success_at = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=False, default="")
    details_json = Column(Text, nullable=False, default="{}")
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class AdminUser(Base):
    __tablename__ = "admin_users"

    id = Column(String(36), primary_key=True)
    username = Column(String(128), nullable=False, unique=True, index=True)
    password_hash = Column(Text, nullable=False)
    role = Column(String(32), nullable=False, default="viewer", index=True)
    active = Column(Boolean, nullable=False, default=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    sessions = relationship("AdminSession", back_populates="user", cascade="all, delete-orphan")


class AdminSession(Base):
    __tablename__ = "admin_sessions"

    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("admin_users.id"), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    last_seen_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    user = relationship("AdminUser", back_populates="sessions")


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    actor = Column(String(255), nullable=False)
    event_type = Column(String(128), nullable=False)
    object_type = Column(String(64), nullable=False, default="")
    object_id = Column(String(64), nullable=False, default="")
    details_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
