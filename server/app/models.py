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
    client_cert_fingerprint = Column(String(64), nullable=True, unique=True, index=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    reboot_required = Column(Boolean, default=False, nullable=False)
    pending_updates = Column(Integer, default=0, nullable=False)
    critical_updates = Column(Integer, default=0, nullable=False)
    inventory_json = Column(Text, nullable=False, default="{}")
    patch_scan_json = Column(Text, nullable=False, default="[]")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    jobs = relationship("PatchJob", back_populates="agent", cascade="all, delete-orphan")
    vulnerabilities = relationship("VulnerabilityFinding", back_populates="agent")
    remediation_evidence = relationship("RemediationEvidence", back_populates="agent")
    risk_snapshots = relationship("AssetRiskSnapshot", back_populates="agent", cascade="all, delete-orphan")
    risk_profile = relationship("AssetRiskProfile", back_populates="agent", cascade="all, delete-orphan", uselist=False)
    risk_acceptances = relationship("AssetRiskAcceptance", back_populates="agent", cascade="all, delete-orphan")
    risk_treatments = relationship("AssetRiskTreatment", back_populates="agent", cascade="all, delete-orphan")


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
    remediation_evidence = relationship("RemediationEvidence", back_populates="campaign")
    approval = relationship("CampaignApproval", back_populates="campaign", uselist=False, cascade="all, delete-orphan")
    preflight_snapshots = relationship("CampaignPreflightSnapshot", back_populates="campaign", cascade="all, delete-orphan")


class CampaignPreflightSnapshot(Base):
    __tablename__ = "campaign_preflight_snapshots"

    id = Column(String(36), primary_key=True)
    campaign_id = Column(String(36), ForeignKey("campaigns.id"), nullable=False, index=True)
    readiness = Column(String(32), nullable=False, index=True)
    deploy_allowed = Column(Boolean, nullable=False, default=False)
    summary_json = Column(Text, nullable=False, default="{}")
    result_json = Column(Text, nullable=False, default="{}")
    result_sha256 = Column(String(64), nullable=False)
    actor = Column(String(255), nullable=False, index=True)
    source = Column(String(64), nullable=False, default="manual")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)

    campaign = relationship("Campaign", back_populates="preflight_snapshots")


class CampaignRingDecision(Base):
    __tablename__ = "campaign_ring_decisions"

    id = Column(String(36), primary_key=True)
    campaign_id = Column(String(36), ForeignKey("campaigns.id"), nullable=False, index=True)
    from_ring = Column(Integer, nullable=False)
    to_ring = Column(Integer, nullable=False)
    decision = Column(String(32), nullable=False, index=True)
    reason = Column(Text, nullable=False)
    health_json = Column(Text, nullable=False, default="{}")
    actor = Column(String(255), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)


class CampaignApproval(Base):
    __tablename__ = "campaign_approvals"

    id = Column(String(36), primary_key=True)
    campaign_id = Column(String(36), ForeignKey("campaigns.id"), nullable=False, unique=True, index=True)
    status = Column(String(32), nullable=False, default="pending", index=True)
    request_reason = Column(Text, nullable=False)
    requested_by = Column(String(255), nullable=False, index=True)
    requested_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    decided_by = Column(String(255), nullable=False, default="")
    decision_reason = Column(Text, nullable=False, default="")
    decided_at = Column(DateTime(timezone=True), nullable=True)

    campaign = relationship("Campaign", back_populates="approval")


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
    remediation_evidence = relationship("RemediationEvidence", back_populates="job", uselist=False)


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
    remediation_evidence = relationship("RemediationEvidence", back_populates="finding")
    sla_exceptions = relationship("VulnerabilitySlaException", back_populates="finding", cascade="all, delete-orphan")


class VulnerabilitySlaException(Base):
    __tablename__ = "vulnerability_sla_exceptions"

    id = Column(String(36), primary_key=True)
    finding_id = Column(String(36), ForeignKey("vulnerability_findings.id"), nullable=False, index=True)
    reason = Column(Text, nullable=False)
    approved_by = Column(String(255), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_by = Column(String(255), nullable=False, default="")
    revoke_reason = Column(Text, nullable=False, default="")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    finding = relationship("VulnerabilityFinding", back_populates="sla_exceptions")


class RemediationProject(Base):
    __tablename__ = "remediation_projects"

    id = Column(String(36), primary_key=True)
    name = Column(String(128), nullable=False, unique=True, index=True)
    patch_ref = Column(String(255), nullable=False, index=True)
    scope_mode = Column(String(32), nullable=False, default="static")
    scope_tag = Column(String(128), nullable=False, default="", index=True)
    scope_filter_json = Column(Text, nullable=False, default="{}")
    owner = Column(String(255), nullable=False)
    due_at = Column(DateTime(timezone=True), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="active", index=True)
    baseline_findings = Column(Integer, nullable=False, default=0)
    baseline_assets = Column(Integer, nullable=False, default=0)
    baseline_risk_reduction = Column(Float, nullable=False, default=0.0)
    scope_snapshot_json = Column(Text, nullable=False, default="{}")
    reason = Column(Text, nullable=False, default="")
    created_by = Column(String(255), nullable=False)
    updated_by = Column(String(255), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    snapshots = relationship("RemediationProjectSnapshot", back_populates="project", cascade="all, delete-orphan")


class RemediationProjectSnapshot(Base):
    __tablename__ = "remediation_project_snapshots"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(String(36), ForeignKey("remediation_projects.id"), nullable=False, index=True)
    tracked_open_findings = Column(Integer, nullable=False)
    current_scope_findings = Column(Integer, nullable=False)
    current_assets = Column(Integer, nullable=False)
    closed_from_baseline = Column(Integer, nullable=False)
    new_findings_since_baseline = Column(Integer, nullable=False)
    scope_departures = Column(Integer, nullable=False)
    progress_percent = Column(Float, nullable=False)
    remaining_risk_reduction = Column(Float, nullable=False, default=0.0)
    realized_risk_reduction = Column(Float, nullable=False, default=0.0)
    risk_reduction_progress_percent = Column(Float, nullable=False, default=0.0)
    expected_progress_percent = Column(Float, nullable=False, default=0.0)
    schedule_variance_percent = Column(Float, nullable=False, default=0.0)
    sla_breached = Column(Integer, nullable=False, default=0)
    kev_findings = Column(Integer, nullable=False, default=0)
    external_assets = Column(Integer, nullable=False, default=0)
    average_age_days = Column(Float, nullable=False, default=0.0)
    oldest_age_days = Column(Float, nullable=False, default=0.0)
    attention_status = Column(String(32), nullable=False, default="on_track")
    pace_status = Column(String(32), nullable=False)
    source = Column(String(64), nullable=False, default="manual")
    captured_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)

    project = relationship("RemediationProject", back_populates="snapshots")


class RemediationEvidence(Base):
    __tablename__ = "remediation_evidence"
    __table_args__ = (
        UniqueConstraint("job_id", name="uq_remediation_evidence_job"),
    )

    id = Column(String(36), primary_key=True)
    finding_id = Column(String(36), ForeignKey("vulnerability_findings.id"), nullable=False, index=True)
    campaign_id = Column(String(36), ForeignKey("campaigns.id"), nullable=False, index=True)
    job_id = Column(String(36), ForeignKey("patch_jobs.id"), nullable=False, index=True)
    agent_id = Column(String(36), ForeignKey("agents.id"), nullable=False, index=True)
    source = Column(String(64), nullable=False, default="openvas")
    cve = Column(String(64), nullable=False, default="", index=True)
    greenbone_task_id = Column(String(64), nullable=False, default="", index=True)
    baseline_report_id = Column(String(255), nullable=False, default="")
    rescan_report_id = Column(String(255), nullable=False, default="", index=True)
    status = Column(String(32), nullable=False, default="waiting_validation", index=True)
    error = Column(Text, nullable=False, default="")
    evidence_json = Column(Text, nullable=False, default="{}")
    requested_at = Column(DateTime(timezone=True), nullable=True)
    verified_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    finding = relationship("VulnerabilityFinding", back_populates="remediation_evidence")
    campaign = relationship("Campaign", back_populates="remediation_evidence")
    job = relationship("PatchJob", back_populates="remediation_evidence")
    agent = relationship("Agent", back_populates="remediation_evidence")


class RiskReductionGoal(Base):
    __tablename__ = "risk_reduction_goals"

    id = Column(String(36), primary_key=True)
    name = Column(String(128), nullable=False, unique=True, index=True)
    scope_tag = Column(String(128), nullable=False, default="", index=True)
    goal_type = Column(String(64), nullable=False, index=True)
    target_value = Column(Float, nullable=False)
    baseline_value = Column(Float, nullable=False)
    owner = Column(String(255), nullable=False)
    due_at = Column(DateTime(timezone=True), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="active", index=True)
    reason = Column(Text, nullable=False, default="")
    created_by = Column(String(255), nullable=False)
    updated_by = Column(String(255), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class AssetRiskPolicy(Base):
    __tablename__ = "asset_risk_policies"

    id = Column(String(36), primary_key=True)
    name = Column(String(128), nullable=False, unique=True, index=True)
    target_tag = Column(String(128), nullable=False, index=True)
    risk_appetite = Column(Integer, nullable=False)
    priority = Column(Integer, nullable=False, default=100)
    enabled = Column(Boolean, nullable=False, default=True)
    reason = Column(Text, nullable=False, default="")
    created_by = Column(String(255), nullable=False, default="")
    updated_by = Column(String(255), nullable=False, default="")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class AssetRiskTreatment(Base):
    __tablename__ = "asset_risk_treatments"

    id = Column(String(36), primary_key=True)
    agent_id = Column(String(36), ForeignKey("agents.id"), nullable=False, index=True)
    owner = Column(String(255), nullable=False)
    action = Column(Text, nullable=False)
    due_at = Column(DateTime(timezone=True), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="planned", index=True)
    created_by = Column(String(255), nullable=False)
    updated_by = Column(String(255), nullable=False)
    completion_evidence = Column(Text, nullable=False, default="")
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    agent = relationship("Agent", back_populates="risk_treatments")


class AssetRiskAcceptance(Base):
    __tablename__ = "asset_risk_acceptances"

    id = Column(String(36), primary_key=True)
    agent_id = Column(String(36), ForeignKey("agents.id"), nullable=False, index=True)
    reason = Column(Text, nullable=False)
    approved_by = Column(String(255), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_by = Column(String(255), nullable=False, default="")
    revoke_reason = Column(Text, nullable=False, default="")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    agent = relationship("Agent", back_populates="risk_acceptances")


class AssetRiskProfile(Base):
    __tablename__ = "asset_risk_profiles"

    agent_id = Column(String(36), ForeignKey("agents.id"), primary_key=True)
    criticality_override = Column(Integer, nullable=True)
    external_override = Column(Boolean, nullable=True)
    controls_json = Column(Text, nullable=True)
    owner = Column(String(255), nullable=False, default="")
    business_service = Column(String(255), nullable=False, default="")
    environment = Column(String(64), nullable=False, default="")
    reason = Column(Text, nullable=False, default="")
    updated_by = Column(String(255), nullable=False, default="")
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    agent = relationship("Agent", back_populates="risk_profile")


class AssetRiskSnapshot(Base):
    __tablename__ = "asset_risk_snapshots"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_id = Column(String(36), ForeignKey("agents.id"), nullable=False, index=True)
    score = Column(Float, nullable=False)
    level = Column(String(32), nullable=False, index=True)
    criticality = Column(Integer, nullable=False)
    external = Column(Boolean, nullable=False, default=False)
    open_findings = Column(Integer, nullable=False, default=0)
    factors_json = Column(Text, nullable=False, default="[]")
    model_version = Column(String(64), nullable=False, default="be_safe_asset_risk_v1")
    decomposition_json = Column(Text, nullable=False, default="[]")
    calculation_json = Column(Text, nullable=False, default="{}")
    risk_policy_json = Column(Text, nullable=False, default="{}")
    risk_appetite = Column(Integer, nullable=False, default=700)
    governance_status = Column(String(64), nullable=False, default="")
    source = Column(String(64), nullable=False, default="manual")
    captured_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)

    agent = relationship("Agent", back_populates="risk_snapshots")


class PatchCatalogEntry(Base):
    __tablename__ = "patch_catalog_entries"

    patch_key = Column(String(255), primary_key=True)
    patch_ref = Column(String(255), nullable=False, index=True)
    vendor = Column(String(128), nullable=False, default="")
    product = Column(String(255), nullable=False, default="")
    title = Column(Text, nullable=False, default="")
    severity = Column(String(32), nullable=False, default="unknown", index=True)
    version = Column(String(128), nullable=False, default="")
    reboot_behavior = Column(String(128), nullable=False, default="")
    source = Column(String(64), nullable=False, default="agent_scan")
    classification = Column(String(64), nullable=False, default="", index=True)
    release_date = Column(DateTime(timezone=True), nullable=True, index=True)
    eol_date = Column(DateTime(timezone=True), nullable=True, index=True)
    supersedes_json = Column(Text, nullable=False, default="[]")
    lifecycle_source = Column(String(64), nullable=False, default="")
    lifecycle_updated_by = Column(String(255), nullable=False, default="")
    lifecycle_updated_at = Column(DateTime(timezone=True), nullable=True)
    enrichment_json = Column(Text, nullable=False, default="{}")
    metadata_json = Column(Text, nullable=False, default="{}")
    first_seen = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)

    observations = relationship("PatchApplicability", back_populates="patch", cascade="all, delete-orphan")


class PatchApplicability(Base):
    __tablename__ = "patch_applicability"
    __table_args__ = (
        UniqueConstraint("patch_key", "agent_id", name="uq_patch_applicability_patch_agent"),
    )

    id = Column(String(36), primary_key=True)
    patch_key = Column(String(255), ForeignKey("patch_catalog_entries.patch_key"), nullable=False, index=True)
    agent_id = Column(String(36), ForeignKey("agents.id"), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="missing", index=True)
    evidence = Column(String(64), nullable=False, default="agent_scan")
    first_seen = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    last_changed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    details_json = Column(Text, nullable=False, default="{}")

    patch = relationship("PatchCatalogEntry", back_populates="observations")
    agent = relationship("Agent")


class PatchMetadataEvidence(Base):
    __tablename__ = "patch_metadata_evidence"
    __table_args__ = (
        UniqueConstraint("patch_key", "source", name="uq_patch_metadata_evidence_patch_source"),
    )

    id = Column(String(36), primary_key=True)
    patch_key = Column(String(255), ForeignKey("patch_catalog_entries.patch_key"), nullable=False, index=True)
    source = Column(String(64), nullable=False, index=True)
    priority = Column(Integer, nullable=False, default=100, index=True)
    observed_at = Column(DateTime(timezone=True), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=True, index=True)
    payload_json = Column(Text, nullable=False, default="{}")
    imported_by = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class PatchFeedProvider(Base):
    __tablename__ = "patch_feed_providers"

    id = Column(String(36), primary_key=True)
    name = Column(String(128), nullable=False, unique=True, index=True)
    provider_type = Column(String(64), nullable=False, default="curated", index=True)
    enabled = Column(Boolean, nullable=False, default=True, index=True)
    priority = Column(Integer, nullable=False, default=500)
    ttl_hours = Column(Integer, nullable=False, default=168)
    interval_seconds = Column(Integer, nullable=False, default=3600)
    failure_threshold = Column(Integer, nullable=False, default=3)
    cooldown_seconds = Column(Integer, nullable=False, default=1800)
    consecutive_failures = Column(Integer, nullable=False, default=0)
    circuit_open_until = Column(DateTime(timezone=True), nullable=True, index=True)
    last_attempt_at = Column(DateTime(timezone=True), nullable=True)
    last_success_at = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=False, default="")
    last_summary_json = Column(Text, nullable=False, default="{}")
    records_json = Column(Text, nullable=False, default="[]")
    provider_config_json = Column(Text, nullable=False, default="{}")
    adapter_state_json = Column(Text, nullable=False, default="{}")
    created_by = Column(String(255), nullable=False)
    updated_by = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class AutoPatchPolicy(Base):
    __tablename__ = "auto_patch_policies"

    id = Column(String(36), primary_key=True)
    name = Column(String(128), nullable=False, unique=True, index=True)
    enabled = Column(Boolean, nullable=False, default=True, index=True)
    mode = Column(String(32), nullable=False, default="recommend", index=True)
    target_os = Column(String(32), nullable=False, default="all", index=True)
    target_tag = Column(String(128), nullable=False, default="", index=True)
    require_kev = Column(Boolean, nullable=False, default=False)
    require_external = Column(Boolean, nullable=False, default=False)
    require_patch_tuesday = Column(Boolean, nullable=False, default=False)
    min_missing_assets = Column(Integer, nullable=False, default=1)
    confidence_floor = Column(String(32), nullable=False, default="insufficient_data")
    allow_eol = Column(Boolean, nullable=False, default=False)
    superseded_action = Column(String(32), nullable=False, default="replace")
    ring_percent = Column(Integer, nullable=False, default=10)
    require_approval = Column(Boolean, nullable=False, default=True)
    require_health_gate = Column(Boolean, nullable=False, default=True)
    require_rollback = Column(Boolean, nullable=False, default=True)
    created_by = Column(String(255), nullable=False)
    updated_by = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class AutoPatchEvaluation(Base):
    __tablename__ = "auto_patch_evaluations"

    id = Column(String(36), primary_key=True)
    actor = Column(String(255), nullable=False, index=True)
    create_drafts = Column(Boolean, nullable=False, default=False, index=True)
    policies = Column(Integer, nullable=False, default=0)
    decisions = Column(Integer, nullable=False, default=0)
    drafts_created = Column(Integer, nullable=False, default=0)
    blocked = Column(Integer, nullable=False, default=0)
    holds = Column(Integer, nullable=False, default=0)
    ready = Column(Integer, nullable=False, default=0)
    summary_json = Column(Text, nullable=False, default="{}")
    result_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)


class PatchFreezeWindow(Base):
    __tablename__ = "patch_freeze_windows"

    id = Column(String(36), primary_key=True)
    name = Column(String(128), nullable=False, unique=True, index=True)
    target_os = Column(String(32), nullable=False, default="all", index=True)
    target_tag = Column(String(128), nullable=False, default="", index=True)
    starts_at = Column(DateTime(timezone=True), nullable=False, index=True)
    ends_at = Column(DateTime(timezone=True), nullable=False, index=True)
    enabled = Column(Boolean, nullable=False, default=True, index=True)
    reason = Column(Text, nullable=False)
    created_by = Column(String(255), nullable=False)
    updated_by = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class CampaignFreezeOverride(Base):
    __tablename__ = "campaign_freeze_overrides"

    id = Column(String(36), primary_key=True)
    campaign_id = Column(String(36), ForeignKey("campaigns.id"), nullable=False, unique=True, index=True)
    reason = Column(Text, nullable=False)
    approved_by = Column(String(255), nullable=False)
    approved_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    revoked_by = Column(String(255), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoke_reason = Column(Text, nullable=False, default="")


class PatchBlockRule(Base):
    __tablename__ = "patch_block_rules"

    id = Column(String(36), primary_key=True)
    name = Column(String(128), nullable=False, unique=True, index=True)
    patch_ref = Column(String(255), nullable=False, index=True)
    target_os = Column(String(32), nullable=False, default="all", index=True)
    target_tag = Column(String(128), nullable=False, default="", index=True)
    reason = Column(Text, nullable=False)
    enabled = Column(Boolean, nullable=False, default=True, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=True, index=True)
    created_by = Column(String(255), nullable=False)
    updated_by = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


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
