import base64
import hashlib
import ipaddress
import hmac
import math
import json
import os
import re
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func
from sqlalchemy.orm import Session, selectinload

from .database import SessionLocal, get_db
from .models import AdminSession, AdminUser, Agent, AssetRiskAcceptance, AssetRiskPolicy, AssetRiskProfile, AssetRiskSnapshot, AssetRiskTreatment, AuditEvent, Campaign, CampaignApproval, CampaignPreflightSnapshot, CampaignRingDecision, IntegrationState, PatchJob, PatchBlockRule, PatchCatalogEntry, PatchApplicability, PatchMetadataEvidence, PatchFeedProvider, AutoPatchPolicy, AutoPatchEvaluation, PatchFreezeWindow, CampaignFreezeOverride, RemediationEvidence, RemediationProject, RemediationProjectSnapshot, RiskReductionGoal, VulnerabilityFinding, VulnerabilitySlaException
from .schemas import AgentMtlsBindRequest, AgentUpdateActivationRequest, AgentUpdateQuarantineClearRequest, AgentUpdateRolloutCreate, AssetRiskAcceptanceCreate, AssetRiskAcceptanceRevoke, AssetRiskPolicyCreate, AssetRiskPolicyUpdate, AssetRiskProfileUpdate, AssetRiskSimulationRequest, AssetRiskTreatmentCreate, AssetRiskTreatmentUpdate, CampaignApprovalDecision, CampaignCreate, HeartbeatRequest, JobResultRequest, JobRetryRequest, LeaseRenewRequest, LoginRequest, PasswordChangeRequest, PatchCatalogLifecycleUpdate, PatchMetadataImportRequest, PatchFeedProviderCreate, PatchFeedProviderUpdate, AutoPatchPolicyCreate, AutoPatchPolicyUpdate, AutoPatchSimulationRequest, PatchFreezeWindowCreate, PatchFreezeWindowUpdate, CampaignFreezeOverrideCreate, CampaignFreezeOverrideRevoke, PatchBlockRuleCreate, PatchBlockRuleUpdate, RegisterRequest, RegisterResponse, RemediationProjectCreate, RemediationProjectUpdate, RemediationRescanRequest, RingAdvance, RiskReductionGoalCreate, RiskReductionGoalUpdate, RollbackRequest, TagUpdate, UserCreateRequest, UserUpdateRequest, VulnerabilityImportRequest, VulnerabilitySlaExceptionCreate, VulnerabilitySlaExceptionRevoke, VulnerabilityStatusUpdate
from .security import create_session, hash_token, new_token, password_hash, password_needs_rehash, password_verify, require_admin, require_enrollment, require_operator, require_viewer, revoke_session, validate_password_strength, validate_role, validate_username
from .greenbone import fetch_findings as fetch_greenbone_findings
from .greenbone import get_config as get_greenbone_config
from .greenbone import public_config as public_greenbone_config
from .greenbone import start_task_rescan as start_greenbone_task_rescan
from .observability import metrics_response, prometheus_http_middleware, readiness_response
from .agent_updates import AgentReleaseError, load_signed_release
from .threat_intel import fetch_epss, fetch_kev, get_config as get_threat_intel_config, public_config as public_threat_intel_config
from .patch_feed_adapters import PatchFeedAdapterError, fetch_patch_feed_records

app = FastAPI(title="Be Safe Patch Manager", version="0.41.0")
STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

app.middleware("http")(prometheus_http_middleware)


def _seconds_setting(name: str, default: int, minimum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, value)


def _int_setting(name: str, default: int, minimum: int, maximum: int | None = None) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def _bool_setting(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


JOB_CLAIM_LEASE_SECONDS = _seconds_setting("JOB_CLAIM_LEASE_SECONDS", 300, 60)
JOB_RUNNING_LEASE_SECONDS = _seconds_setting("JOB_RUNNING_LEASE_SECONDS", 7200, 300)
AGENT_ACTIVATION_CONFIRM_TIMEOUT_SECONDS = _seconds_setting(
    "AGENT_ACTIVATION_CONFIRM_TIMEOUT_SECONDS",
    900,
    60,
)
AGENT_UPDATE_APPROVAL_TTL_SECONDS = _seconds_setting(
    "AGENT_UPDATE_APPROVAL_TTL_SECONDS",
    1800,
    300,
)
AGENT_UPDATE_MAX_HEARTBEAT_AGE_SECONDS = _seconds_setting(
    "AGENT_UPDATE_MAX_HEARTBEAT_AGE_SECONDS",
    900,
    60,
)
AGENT_MTLS_REQUIRED = _bool_setting("AGENT_MTLS_REQUIRED", False)
AGENT_MIN_VERSION = os.getenv("AGENT_MIN_VERSION", "0.13.0").strip() or "0.13.0"
AGENT_MIN_PROTOCOL = _seconds_setting("AGENT_MIN_PROTOCOL", 2, 1)
AGENT_ENFORCE_COMPATIBILITY = _bool_setting("AGENT_ENFORCE_COMPATIBILITY", False)
AGENT_UPDATE_ENABLED = _bool_setting("AGENT_UPDATE_ENABLED", False)
ASSET_RISK_APPETITE = _int_setting("ASSET_RISK_APPETITE", 700, 1, 1000)
ASSET_RISK_HISTORY_RETENTION_DAYS = _int_setting("ASSET_RISK_HISTORY_RETENTION_DAYS", 180, 7, 3650)
AGENT_RELEASE_DIR = Path(os.getenv("AGENT_RELEASE_DIR", "/agent-releases"))
AGENT_UPDATE_PUBLIC_KEY_FILE = Path(
    os.getenv("AGENT_UPDATE_PUBLIC_KEY_FILE", "/update-trust/agent-update-public.pem")
)
TERMINAL_JOB_STATUSES = {"success", "failed", "skipped"}


def now():
    return datetime.now(timezone.utc)


def dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def load(value: str, fallback):
    try:
        return json.loads(value)
    except Exception:
        return fallback


def audit(db: Session, actor: str, event_type: str, object_type: str = "", object_id: str = "", details=None):
    db.add(AuditEvent(
        actor=actor,
        event_type=event_type,
        object_type=object_type,
        object_id=object_id,
        details_json=dump(details or {}),
    ))
    db.commit()


def serialize_admin_user(user: AdminUser):
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "active": user.active,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
        "created_at": user.created_at.isoformat(),
        "updated_at": user.updated_at.isoformat(),
    }


def ensure_bootstrap_admin():
    db = SessionLocal()
    try:
        if db.query(AdminUser).count() > 0:
            return

        username_raw = os.getenv("BOOTSTRAP_ADMIN_USERNAME", "").strip()
        password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "")
        if not username_raw or not password:
            raise RuntimeError(
                "no administrative users exist; configure BOOTSTRAP_ADMIN_USERNAME and BOOTSTRAP_ADMIN_PASSWORD"
            )

        try:
            username = validate_username(username_raw)
            validate_password_strength(password)
        except ValueError as exc:
            raise RuntimeError(f"invalid bootstrap administrator: {exc}") from exc

        user = AdminUser(
            id=str(uuid.uuid4()),
            username=username,
            password_hash=password_hash(password),
            role="admin",
            active=True,
        )
        db.add(user)
        db.commit()
        audit(
            db,
            "system",
            "auth.bootstrap_admin.created",
            "user",
            user.id,
            {"username": user.username, "role": user.role},
        )
    finally:
        db.close()


@app.on_event("startup")
def bootstrap_authentication():
    ensure_bootstrap_admin()


def normalize_client_cert_fingerprint(value) -> str:
    if not isinstance(value, str):
        return ""
    normalized = re.sub(r"[^0-9a-fA-F]", "", value).lower()
    if not normalized:
        return ""
    if len(normalized) != 40 or not re.fullmatch(r"[0-9a-f]{40}", normalized):
        raise HTTPException(status_code=400, detail="invalid client certificate fingerprint")
    return normalized


def require_agent_mtls_fingerprint(value) -> str:
    fingerprint = normalize_client_cert_fingerprint(value)
    if AGENT_MTLS_REQUIRED and not fingerprint:
        raise HTTPException(status_code=401, detail="mTLS client certificate is required")
    return fingerprint


def get_agent(
    db: Session,
    agent_id: str,
    token: str | None,
    client_cert_fingerprint=None,
) -> Agent:
    if not token:
        raise HTTPException(status_code=401, detail="missing agent token")
    agent = db.get(Agent, agent_id)
    if not agent or not hmac.compare_digest(agent.token_hash, hash_token(token)):
        raise HTTPException(status_code=401, detail="invalid agent credentials")

    presented = require_agent_mtls_fingerprint(client_cert_fingerprint)
    bound = str(agent.client_cert_fingerprint or "").lower()

    if AGENT_MTLS_REQUIRED:
        if not bound:
            raise HTTPException(status_code=401, detail="agent is not bound to an mTLS certificate")
        if not hmac.compare_digest(bound, presented):
            raise HTTPException(status_code=401, detail="mTLS certificate does not match this agent")
    elif bound and presented and not hmac.compare_digest(bound, presented):
        raise HTTPException(status_code=401, detail="mTLS certificate does not match this agent")

    return agent



def _version_tuple(value: str):
    text = str(value or "").strip()
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[-+].*)?", text)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def version_at_least(current: str, minimum: str) -> bool:
    current_tuple = _version_tuple(current)
    minimum_tuple = _version_tuple(minimum)
    if current_tuple is None or minimum_tuple is None:
        return False
    return current_tuple >= minimum_tuple


def agent_heartbeat_fresh(agent: Agent, max_age_seconds: int | None = None) -> bool:
    if not agent.last_seen:
        return False
    seen = agent.last_seen
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=timezone.utc)
    age = (now() - seen).total_seconds()
    limit = max_age_seconds or AGENT_UPDATE_MAX_HEARTBEAT_AGE_SECONDS
    return 0 <= age <= limit


def agent_runtime_metadata(agent: Agent) -> dict:
    inventory = load(agent.inventory_json, {})
    runtime = inventory.get("agent") if isinstance(inventory.get("agent"), dict) else {}
    version = str(runtime.get("version") or "").strip()

    try:
        protocol = int(runtime.get("protocol") or 0)
    except (TypeError, ValueError):
        protocol = 0

    raw_capabilities = runtime.get("capabilities")
    capabilities = sorted({
        str(item).strip()
        for item in (raw_capabilities if isinstance(raw_capabilities, list) else [])
        if str(item).strip()
    })

    known = bool(version and protocol)
    version_supported = version_at_least(version, AGENT_MIN_VERSION)
    protocol_supported = protocol >= AGENT_MIN_PROTOCOL
    if not known:
        status = "unknown"
    elif not version_supported:
        status = "outdated"
    elif not protocol_supported:
        status = "protocol_unsupported"
    else:
        status = "supported"

    return {
        "version": version,
        "protocol": protocol,
        "capabilities": capabilities,
        "known": known,
        "minimum_version": AGENT_MIN_VERSION,
        "minimum_protocol": AGENT_MIN_PROTOCOL,
        "version_supported": version_supported,
        "protocol_supported": protocol_supported,
        "status": status,
        "enforced": AGENT_ENFORCE_COMPATIBILITY,
    }


def required_capabilities_for_job(job: PatchJob) -> list[str]:
    payload = load(job.payload_json, {})
    required = {"job_leases_v1"}

    if job.action == "scan_updates":
        required.add("scan_updates")
    elif job.action == "install_updates":
        required.add("install_updates")
        if payload.get("prepare_rollback", True):
            required.add("rollback_checkpoint_v1")
        health_policy = payload.get("health_policy")
        if isinstance(health_policy, dict) and health_policy.get("enabled"):
            required.add("health_telemetry_v1")
    elif job.action == "rollback_checkpoint":
        required.add("rollback_restore_v1")
    elif job.action == "activate_agent_update":
        required.add("signed_update_activation_v1")
    elif job.action == "clear_agent_update_quarantine":
        required.add("signed_update_quarantine_v1")

    return sorted(required)


def job_agent_compatibility(job: PatchJob, agent: Agent | None = None) -> dict:
    agent = agent or job.agent
    if not agent:
        return {
            "compatible": False,
            "status": "agent_unavailable",
            "required_capabilities": required_capabilities_for_job(job),
            "missing_capabilities": [],
            "agent": {},
        }

    runtime = agent_runtime_metadata(agent)
    required = required_capabilities_for_job(job)
    available = set(runtime.get("capabilities") or [])
    missing = sorted(set(required) - available)

    compatible = (
        runtime.get("status") == "supported"
        and not missing
    )
    if runtime.get("status") != "supported":
        status = runtime.get("status") or "unknown"
    elif missing:
        status = "missing_capabilities"
    else:
        status = "supported"

    return {
        "compatible": compatible,
        "status": status,
        "required_capabilities": required,
        "missing_capabilities": missing,
        "agent": runtime,
        "enforced": AGENT_ENFORCE_COMPATIBILITY,
    }



def serialize_agent(a: Agent):
    return {
        "id": a.id,
        "hostname": a.hostname,
        "os_family": a.os_family,
        "os_name": a.os_name,
        "os_version": a.os_version,
        "arch": a.arch,
        "ip_address": a.ip_address,
        "tags": load(a.tags, []),
        "mtls": {
            "required": AGENT_MTLS_REQUIRED,
            "bound": bool(a.client_cert_fingerprint),
            "fingerprint": a.client_cert_fingerprint or "",
        },
        "last_seen": a.last_seen.isoformat() if a.last_seen else None,
        "reboot_required": a.reboot_required,
        "pending_updates": a.pending_updates,
        "critical_updates": a.critical_updates,
        "inventory": load(a.inventory_json, {}),
        "patch_scan": load(a.patch_scan_json, []),
        "runtime": agent_runtime_metadata(a),
        "created_at": a.created_at.isoformat(),
    }





CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


def normalize_cve(value: str) -> str:
    value = str(value or "").strip().upper()
    return value if CVE_RE.fullmatch(value) else ""


def severity_from_cvss(cvss: float, explicit: str = "") -> str:
    explicit = str(explicit or "").strip().lower()
    aliases = {
        "critical": "critical",
        "high": "high",
        "important": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "log": "low",
        "info": "info",
        "informational": "info",
    }
    if explicit in aliases:
        return aliases[explicit]
    score = float(cvss or 0)
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


VULNERABILITY_SLA_HOURS = {
    "critical": _seconds_setting("VULNERABILITY_SLA_CRITICAL_HOURS", 72, 1),
    "high": _seconds_setting("VULNERABILITY_SLA_HIGH_HOURS", 168, 1),
    "medium": _seconds_setting("VULNERABILITY_SLA_MEDIUM_HOURS", 720, 1),
    "low": _seconds_setting("VULNERABILITY_SLA_LOW_HOURS", 2160, 1),
    "info": _seconds_setting("VULNERABILITY_SLA_INFO_HOURS", 4320, 1),
    "unknown": _seconds_setting("VULNERABILITY_SLA_UNKNOWN_HOURS", 720, 1),
}
VULNERABILITY_SLA_DUE_SOON_HOURS = _seconds_setting(
    "VULNERABILITY_SLA_DUE_SOON_HOURS",
    24,
    1,
)


def serialize_sla_exception(item: VulnerabilitySlaException, reference: datetime | None = None) -> dict:
    reference = reference or now()
    expires_at = item.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    revoked_at = item.revoked_at
    if revoked_at and revoked_at.tzinfo is None:
        revoked_at = revoked_at.replace(tzinfo=timezone.utc)
    active = revoked_at is None and expires_at > reference
    return {
        "id": item.id,
        "finding_id": item.finding_id,
        "reason": item.reason,
        "approved_by": item.approved_by,
        "expires_at": expires_at.isoformat(),
        "revoked_at": revoked_at.isoformat() if revoked_at else None,
        "revoked_by": item.revoked_by,
        "revoke_reason": item.revoke_reason,
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "active": active,
        "expired": revoked_at is None and expires_at <= reference,
    }


def active_sla_exception(finding: VulnerabilityFinding, reference: datetime | None = None):
    reference = reference or now()
    candidates = sorted(
        list(finding.sla_exceptions or []),
        key=lambda item: item.created_at or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    for item in candidates:
        data = serialize_sla_exception(item, reference)
        if data["active"]:
            return item
    return None


def vulnerability_sla(finding: VulnerabilityFinding, reference: datetime | None = None) -> dict:
    reference = reference or now()
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)

    severity = str(finding.severity or "unknown").strip().lower()
    target_hours = int(VULNERABILITY_SLA_HOURS.get(severity, VULNERABILITY_SLA_HOURS["unknown"]))
    first_seen = finding.first_seen or finding.created_at or reference
    if first_seen.tzinfo is None:
        first_seen = first_seen.replace(tzinfo=timezone.utc)

    due_at = first_seen + timedelta(hours=target_hours)
    age_hours = max(0.0, (reference - first_seen).total_seconds() / 3600.0)
    remaining_hours = (due_at - reference).total_seconds() / 3600.0
    exception = active_sla_exception(finding, reference)
    open_finding = finding.status == "open"
    active = open_finding and exception is None

    if exception is not None:
        state = "exception"
    elif not open_finding:
        state = "excluded"
    elif remaining_hours < 0:
        state = "breached"
    elif remaining_hours <= VULNERABILITY_SLA_DUE_SOON_HOURS:
        state = "due_soon"
    else:
        state = "within_sla"

    return {
        "state": state,
        "active": active,
        "open": open_finding,
        "target_hours": target_hours,
        "age_hours": round(age_hours, 1),
        "remaining_hours": round(remaining_hours, 1),
        "due_at": due_at.isoformat(),
        "breached": state == "breached",
        "due_soon": state == "due_soon",
        "exception": serialize_sla_exception(exception, reference) if exception else None,
    }


def remediation_recommendation(finding: VulnerabilityFinding, reference: datetime | None = None) -> dict:
    reference = reference or now()
    risk = vulnerability_risk(finding, reference)
    sla = vulnerability_sla(finding, reference)
    matched = bool(finding.agent_id and finding.agent)
    patch_refs = load(finding.patch_refs_json, [])
    patchable = bool(patch_refs)
    reasons = []

    priority = float(risk["score"])
    if sla["state"] == "breached":
        priority += 20
        reasons.append("SLA vencido")
    elif sla["state"] == "due_soon":
        priority += 10
        reasons.append("SLA próximo do vencimento")
    elif sla["state"] == "exception":
        reasons.append("exceção de SLA ativa")

    if risk["kev"]:
        priority += 10
        reasons.append("CVE presente no CISA KEV")
    if risk["epss"] is not None and risk["epss"] >= 0.5:
        reasons.append(f"EPSS {round(risk['epss'] * 100)}%")
    if not matched:
        reasons.append("finding sem endpoint gerenciado correlacionado")
    if matched and not patchable:
        reasons.append("sem referência de patch/KB normalizada")

    priority = round(min(100.0, priority), 1)

    if finding.status != "open":
        action = "none"
        eligible = False
        reasons.append("finding não está aberto")
    elif sla["state"] == "exception":
        action = "exception_active"
        eligible = False
    elif not matched:
        action = "correlate_asset"
        eligible = False
    elif not patchable:
        action = "scan_or_manual_triage"
        eligible = True
    elif risk["level"] == "urgent" or sla["state"] == "breached":
        action = "patch_now"
        eligible = True
    elif risk["level"] == "high" or sla["state"] == "due_soon":
        action = "schedule_patch"
        eligible = True
    else:
        action = "plan_patch"
        eligible = True

    return {
        "priority_score": priority,
        "action": action,
        "eligible_for_campaign": eligible,
        "matched": matched,
        "patchable": patchable,
        "patch_refs": patch_refs,
        "risk": risk,
        "sla": sla,
        "reasons": reasons,
    }


def remediation_queue_report(db: Session, reference: datetime | None = None) -> dict:
    reference = reference or now()
    findings = db.query(VulnerabilityFinding).filter(
        VulnerabilityFinding.status == "open"
    ).all()

    items = []
    summary = {
        "total_open": len(findings),
        "patch_now": 0,
        "schedule_patch": 0,
        "plan_patch": 0,
        "scan_or_manual_triage": 0,
        "correlate_asset": 0,
        "exception_active": 0,
        "eligible_for_campaign": 0,
    }

    for finding in findings:
        recommendation = remediation_recommendation(finding, reference)
        action = recommendation["action"]
        summary[action] = summary.get(action, 0) + 1
        if recommendation["eligible_for_campaign"]:
            summary["eligible_for_campaign"] += 1

        items.append({
            "id": finding.id,
            "cve": finding.cve,
            "title": finding.title,
            "severity": finding.severity,
            "cvss": finding.cvss,
            "agent_id": finding.agent_id,
            "hostname": finding.agent.hostname if finding.agent else "",
            "source": finding.source,
            "last_seen": finding.last_seen.isoformat() if finding.last_seen else None,
            "recommendation": recommendation,
        })

    action_rank = {
        "patch_now": 0,
        "schedule_patch": 1,
        "scan_or_manual_triage": 2,
        "plan_patch": 3,
        "correlate_asset": 4,
        "exception_active": 5,
        "none": 9,
    }
    items.sort(key=lambda item: (
        action_rank.get(item["recommendation"]["action"], 8),
        -item["recommendation"]["priority_score"],
        -float(item.get("cvss") or 0),
    ))

    return {
        "generated_at": reference.isoformat(),
        "summary": summary,
        "items": items,
    }


def risk_reduction_opportunities_report(
    db: Session,
    reference: datetime | None = None,
    limit: int = 100,
) -> dict:
    reference = reference or now()
    agents = db.query(Agent).options(
        selectinload(Agent.vulnerabilities),
        selectinload(Agent.risk_profile),
    ).order_by(Agent.hostname.asc()).all()
    policies = db.query(AssetRiskPolicy).filter(
        AssetRiskPolicy.enabled.is_(True)
    ).order_by(
        AssetRiskPolicy.priority.desc(),
        AssetRiskPolicy.name.asc(),
    ).all()
    opportunities = []

    for agent in agents:
        findings = [
            finding
            for finding in (agent.vulnerabilities or [])
            if finding.status == "open"
        ]
        if not findings:
            continue

        before = asset_risk_score(agent, findings, reference)
        policy = effective_asset_risk_policy(db, agent, policies=policies)

        for finding in findings:
            after_findings = [
                candidate for candidate in findings
                if candidate.id != finding.id
            ]
            after = asset_risk_score(agent, after_findings, reference)
            delta = round(max(0.0, before["score"] - after["score"]), 1)
            reduction_percent = (
                round((delta / before["score"]) * 100.0, 1)
                if before["score"] > 0
                else 0.0
            )
            finding_risk = finding_detection_risk(finding, reference)
            sla = vulnerability_sla(finding, reference)
            recommendation = remediation_recommendation(finding, reference)

            opportunities.append({
                "finding_id": finding.id,
                "agent_id": agent.id,
                "hostname": agent.hostname,
                "cve": finding.cve,
                "title": finding.title,
                "severity": finding.severity,
                "cvss": finding.cvss,
                "finding_risk": finding_risk,
                "sla": sla,
                "recommendation": {
                    "action": recommendation["action"],
                    "priority_score": recommendation["priority_score"],
                    "eligible_for_campaign": recommendation["eligible_for_campaign"],
                },
                "before_score": before["score"],
                "projected_score": after["score"],
                "risk_appetite": policy["risk_appetite"],
                "risk_reduction": delta,
                "reduction_percent": reduction_percent,
                "crosses_below_appetite": (
                    before["score"] >= policy["risk_appetite"]
                    and after["score"] < policy["risk_appetite"]
                ),
            })

    opportunities.sort(key=lambda item: (
        -item["risk_reduction"],
        -item["reduction_percent"],
        -item["recommendation"]["priority_score"],
        -float(item.get("cvss") or 0),
        item["hostname"].lower(),
    ))

    opportunities = opportunities[:max(1, min(limit, 500))]
    return {
        "generated_at": reference.isoformat(),
        "mode": "simulation_only",
        "summary": {
            "opportunities": len(opportunities),
            "crosses_below_appetite": sum(
                1 for item in opportunities
                if item["crosses_below_appetite"]
            ),
        },
        "items": opportunities,
        "note": "Each opportunity is an independent single-finding simulation. Reductions are not additive across rows.",
    }


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


RISK_REDUCTION_GOAL_TYPES = {
    "average_asset_risk_max": "Average Asset Risk",
    "assets_above_appetite_max": "Assets Above Appetite",
    "open_findings_max": "Open Findings",
    "critical_high_assets_max": "Critical/High Risk Assets",
}


def _goal_scope_agent_ids(db: Session, scope_tag: str) -> set[str] | None:
    tag = str(scope_tag or "").strip().lower()
    if not tag:
        return None
    return agent_ids_matching_risk_tags(db, {tag})


def _goal_metric_value(
    db: Session,
    goal_type: str,
    scope_tag: str = "",
    reference: datetime | None = None,
) -> tuple[float, int]:
    reference = reference or now()
    if goal_type not in RISK_REDUCTION_GOAL_TYPES:
        raise HTTPException(status_code=400, detail="unsupported risk reduction goal type")

    scoped_ids = _goal_scope_agent_ids(db, scope_tag)
    if scoped_ids is not None and not scoped_ids:
        return 0.0, 0

    report = asset_risk_report(
        db,
        reference,
        agent_ids=scoped_ids,
    )
    assets = report["assets"]
    if goal_type == "average_asset_risk_max":
        value = float(report["summary"]["average_score"])
    elif goal_type == "assets_above_appetite_max":
        value = float(report["summary"]["above_risk_appetite"])
    elif goal_type == "open_findings_max":
        value = float(sum(int(row["risk"].get("open_findings") or 0) for row in assets))
    else:
        value = float(
            report["summary"]["critical"] + report["summary"]["high"]
        )
    return round(value, 1), len(assets)


def serialize_risk_reduction_goal(
    db: Session,
    goal: RiskReductionGoal,
    reference: datetime | None = None,
) -> dict:
    reference = reference or now()
    current_value, scoped_assets = _goal_metric_value(
        db,
        goal.goal_type,
        goal.scope_tag,
        reference,
    )
    baseline = float(goal.baseline_value)
    target = float(goal.target_value)
    denominator = baseline - target
    progress = (
        max(0.0, min(100.0, ((baseline - current_value) / denominator) * 100.0))
        if denominator > 0
        else 100.0
    )
    achieved = current_value <= target

    created_at = goal.created_at or reference
    due_at = goal.due_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    if due_at.tzinfo is None:
        due_at = due_at.replace(tzinfo=timezone.utc)

    total_seconds = max(1.0, (due_at - created_at).total_seconds())
    elapsed_fraction = max(
        0.0,
        min(1.0, (reference - created_at).total_seconds() / total_seconds),
    )
    expected_value = baseline - (denominator * elapsed_fraction)

    if goal.status == "cancelled":
        pace_status = "cancelled"
    elif goal.status == "completed":
        pace_status = "completed"
    elif achieved:
        pace_status = "achieved"
    elif reference > due_at:
        pace_status = "overdue"
    elif current_value <= expected_value:
        pace_status = "on_track"
    else:
        pace_status = "at_risk"

    return {
        "id": goal.id,
        "name": goal.name,
        "scope_tag": goal.scope_tag,
        "scope": "all_managed_assets" if not goal.scope_tag else f"tag:{goal.scope_tag}",
        "scoped_assets": scoped_assets,
        "goal_type": goal.goal_type,
        "goal_label": RISK_REDUCTION_GOAL_TYPES.get(goal.goal_type, goal.goal_type),
        "baseline_value": round(baseline, 1),
        "target_value": round(target, 1),
        "current_value": current_value,
        "remaining_to_target": round(max(0.0, current_value - target), 1),
        "progress_percent": round(progress, 1),
        "expected_value_now": round(expected_value, 1),
        "pace_status": pace_status,
        "achieved": achieved,
        "owner": goal.owner,
        "due_at": due_at.isoformat(),
        "status": goal.status,
        "reason": goal.reason,
        "created_by": goal.created_by,
        "updated_by": goal.updated_by,
        "completed_at": goal.completed_at.isoformat() if goal.completed_at else None,
        "created_at": created_at.isoformat(),
        "updated_at": goal.updated_at.isoformat() if goal.updated_at else None,
    }


def risk_reduction_goals_report(
    db: Session,
    reference: datetime | None = None,
) -> dict:
    reference = reference or now()
    goals = db.query(RiskReductionGoal).order_by(
        RiskReductionGoal.status.asc(),
        RiskReductionGoal.due_at.asc(),
        RiskReductionGoal.name.asc(),
    ).all()
    items = [
        serialize_risk_reduction_goal(db, goal, reference)
        for goal in goals
    ]
    return {
        "generated_at": reference.isoformat(),
        "summary": {
            "total": len(items),
            "active": sum(1 for item in items if item["status"] == "active"),
            "achieved": sum(1 for item in items if item["pace_status"] in {"achieved", "completed"}),
            "on_track": sum(1 for item in items if item["pace_status"] == "on_track"),
            "at_risk": sum(1 for item in items if item["pace_status"] == "at_risk"),
            "overdue": sum(1 for item in items if item["pace_status"] == "overdue"),
        },
        "items": items,
        "goal_types": RISK_REDUCTION_GOAL_TYPES,
        "note": "Goal baselines are frozen at creation. Current values are recalculated from the live managed-asset scope.",
    }


def business_context_report(
    db: Session,
    reference: datetime | None = None,
) -> dict:
    reference = reference or now()
    report = asset_risk_report(db, reference)

    def aggregate(field: str, unassigned: str) -> list[dict]:
        buckets: dict[str, dict] = {}
        for row in report["assets"]:
            profile = row.get("risk_profile") or {}
            raw_label = str(profile.get(field) or "").strip()
            label = raw_label or unassigned
            bucket = buckets.setdefault(label, {
                "name": label,
                "asset_count": 0,
                "scores": [],
                "critical": 0,
                "high": 0,
                "open_findings": 0,
                "above_appetite": 0,
                "accepted": 0,
                "in_treatment": 0,
                "treatment_overdue": 0,
                "untreated": 0,
                "with_owner": 0,
            })
            risk = row["risk"]
            bucket["asset_count"] += 1
            bucket["scores"].append(float(risk["score"]))
            bucket["critical"] += 1 if risk["level"] == "critical" else 0
            bucket["high"] += 1 if risk["level"] == "high" else 0
            bucket["open_findings"] += int(risk.get("open_findings") or 0)
            bucket["above_appetite"] += 1 if risk.get("above_risk_appetite") else 0
            status = str(risk.get("governance_status") or "")
            bucket["accepted"] += 1 if status == "accepted" else 0
            bucket["in_treatment"] += 1 if status == "in_treatment" else 0
            bucket["treatment_overdue"] += 1 if status == "treatment_overdue" else 0
            bucket["untreated"] += 1 if status == "above_appetite" else 0
            bucket["with_owner"] += 1 if str(profile.get("owner") or "").strip() else 0

        items = []
        for bucket in buckets.values():
            above = bucket["above_appetite"]
            governed = bucket["accepted"] + bucket["in_treatment"] + bucket["treatment_overdue"]
            items.append({
                "name": bucket["name"],
                "asset_count": bucket["asset_count"],
                "average_risk": round(sum(bucket["scores"]) / len(bucket["scores"]), 1) if bucket["scores"] else 0.0,
                "max_risk": round(max(bucket["scores"]), 1) if bucket["scores"] else 0.0,
                "critical": bucket["critical"],
                "high": bucket["high"],
                "open_findings": bucket["open_findings"],
                "above_appetite": above,
                "accepted": bucket["accepted"],
                "in_treatment": bucket["in_treatment"],
                "treatment_overdue": bucket["treatment_overdue"],
                "untreated": bucket["untreated"],
                "governance_coverage_percent": round(governed / above * 100.0, 1) if above else 100.0,
                "owner_coverage_percent": round(bucket["with_owner"] / bucket["asset_count"] * 100.0, 1) if bucket["asset_count"] else 0.0,
            })
        items.sort(key=lambda item: (-item["average_risk"], -item["asset_count"], item["name"].lower()))
        return items

    return {
        "generated_at": reference.isoformat(),
        "by_owner": aggregate("owner", "sem owner"),
        "by_business_service": aggregate("business_service", "sem business service"),
        "by_environment": aggregate("environment", "sem environment"),
        "summary": {
            "assets": report["summary"]["assets"],
            "owner_coverage_percent": (
                round(
                    report["summary"]["assets_with_owner"] / report["summary"]["assets"] * 100.0,
                    1,
                )
                if report["summary"]["assets"]
                else 0.0
            ),
            "critical_high_without_owner": report["summary"]["critical_high_without_owner"],
        },
        "note": "Business Context segments reuse the existing Asset Risk model. No additional hidden score multiplier is applied.",
    }


def remediation_performance_report(
    db: Session,
    reference: datetime | None = None,
) -> dict:
    reference = reference or now()
    remediated = db.query(VulnerabilityFinding).filter(
        VulnerabilityFinding.status == "remediated",
        VulnerabilityFinding.resolved_at.is_not(None),
    ).all()

    mttr_hours = []
    by_severity_raw: dict[str, list[float]] = {}
    target_met = 0
    target_measured = 0

    for finding in remediated:
        first_seen = finding.first_seen or finding.created_at
        resolved_at = finding.resolved_at
        if not first_seen or not resolved_at:
            continue
        if first_seen.tzinfo is None:
            first_seen = first_seen.replace(tzinfo=timezone.utc)
        if resolved_at.tzinfo is None:
            resolved_at = resolved_at.replace(tzinfo=timezone.utc)
        duration = max(0.0, (resolved_at - first_seen).total_seconds() / 3600.0)
        mttr_hours.append(duration)
        severity = str(finding.severity or "unknown").lower()
        by_severity_raw.setdefault(severity, []).append(duration)
        target = VULNERABILITY_SLA_HOURS.get(severity, VULNERABILITY_SLA_HOURS["unknown"])
        target_measured += 1
        target_met += 1 if duration <= target else 0

    evidence_counts = {
        str(status or "unknown"): int(count)
        for status, count in db.query(
            RemediationEvidence.status,
            func.count(RemediationEvidence.id),
        ).group_by(RemediationEvidence.status).all()
    }
    evidence_terminal = sum(
        evidence_counts.get(status, 0)
        for status in ("verified", "still_detected", "error")
    )
    evidence_verified = evidence_counts.get("verified", 0)

    patch_jobs = db.query(PatchJob).filter(
        PatchJob.action == "install_updates",
        PatchJob.status.in_(["success", "failed"]),
    ).all()
    job_durations = []
    success_jobs = 0
    failed_jobs = 0
    for job in patch_jobs:
        success_jobs += 1 if job.status == "success" else 0
        failed_jobs += 1 if job.status == "failed" else 0
        if job.started_at and job.finished_at:
            started = job.started_at
            finished = job.finished_at
            if started.tzinfo is None:
                started = started.replace(tzinfo=timezone.utc)
            if finished.tzinfo is None:
                finished = finished.replace(tzinfo=timezone.utc)
            job_durations.append(max(0.0, (finished - started).total_seconds() / 60.0))

    sla = vulnerability_sla_report(db, reference)
    by_severity = {
        severity: {
            "remediated": len(values),
            "median_mttr_hours": round(_median(values), 1) if _median(values) is not None else None,
            "average_mttr_hours": round(sum(values) / len(values), 1) if values else None,
        }
        for severity, values in sorted(by_severity_raw.items())
    }

    completed_jobs = success_jobs + failed_jobs
    return {
        "generated_at": reference.isoformat(),
        "summary": {
            "remediated_findings": len(mttr_hours),
            "median_mttr_hours": round(_median(mttr_hours), 1) if _median(mttr_hours) is not None else None,
            "average_mttr_hours": round(sum(mttr_hours) / len(mttr_hours), 1) if mttr_hours else None,
            "raw_sla_target_met_percent": round(target_met / target_measured * 100.0, 1) if target_measured else None,
            "verified_evidence_rate_percent": round(evidence_verified / evidence_terminal * 100.0, 1) if evidence_terminal else None,
            "patch_job_success_rate_percent": round(success_jobs / completed_jobs * 100.0, 1) if completed_jobs else None,
            "median_patch_job_minutes": round(_median(job_durations), 1) if _median(job_durations) is not None else None,
            "open_sla_breaches": sla["summary"]["breached"],
        },
        "evidence": evidence_counts,
        "patch_jobs": {
            "success": success_jobs,
            "failed": failed_jobs,
            "completed": completed_jobs,
        },
        "by_severity": by_severity,
        "note": "MTTR uses first_seen to resolved_at for findings marked remediated. raw_sla_target_met_percent compares that duration to the severity target without reconstructing historical exception pause intervals.",
    }


def active_threat_watch_report(
    db: Session,
    reference: datetime | None = None,
    epss_threshold: float = 0.70,
    limit: int = 50,
) -> dict:
    reference = reference or now()
    findings = db.query(VulnerabilityFinding).options(
        selectinload(VulnerabilityFinding.agent).selectinload(Agent.risk_profile),
    ).filter(
        VulnerabilityFinding.status == "open",
        VulnerabilityFinding.cve != "",
    ).all()

    groups: dict[str, dict] = {}
    for finding in findings:
        detection = finding_detection_risk(finding, reference)
        active_signal = (
            detection["kev"]
            or detection["ransomware"]
            or (detection["epss"] is not None and detection["epss"] >= epss_threshold)
        )
        if not active_signal:
            continue

        cve = finding.cve.upper()
        group = groups.setdefault(cve, {
            "cve": cve,
            "finding_ids": set(),
            "asset_ids": set(),
            "hostnames": set(),
            "patch_refs": set(),
            "kev": False,
            "ransomware": False,
            "max_epss": None,
            "max_risk_score": 0.0,
            "max_cvss": 0.0,
            "oldest_age_days": 0.0,
            "external_assets": set(),
            "critical_assets": set(),
        })
        group["finding_ids"].add(finding.id)
        if finding.agent_id:
            group["asset_ids"].add(finding.agent_id)
        if finding.agent:
            group["hostnames"].add(finding.agent.hostname)
            if asset_exposure(finding.agent)["external"]:
                group["external_assets"].add(finding.agent.id)
            if asset_criticality(finding.agent)["score"] >= 5:
                group["critical_assets"].add(finding.agent.id)
        group["patch_refs"].update({
            str(ref).strip()
            for ref in load(finding.patch_refs_json, [])
            if str(ref).strip()
        })
        group["kev"] = group["kev"] or detection["kev"]
        group["ransomware"] = group["ransomware"] or detection["ransomware"]
        if detection["epss"] is not None:
            group["max_epss"] = max(group["max_epss"] or 0.0, detection["epss"])
        group["max_risk_score"] = max(group["max_risk_score"], detection["score"])
        group["max_cvss"] = max(group["max_cvss"], detection["cvss"])
        group["oldest_age_days"] = max(group["oldest_age_days"], detection["age_days"])

    items = []
    for group in groups.values():
        signals = []
        if group["kev"]:
            signals.append("CISA KEV")
        if group["ransomware"]:
            signals.append("ransomware")
        if group["max_epss"] is not None and group["max_epss"] >= epss_threshold:
            signals.append(f"EPSS {group['max_epss']:.0%}")
        items.append({
            "cve": group["cve"],
            "signals": signals,
            "kev": group["kev"],
            "ransomware": group["ransomware"],
            "max_epss": group["max_epss"],
            "max_risk_score": round(group["max_risk_score"], 1),
            "max_cvss": round(group["max_cvss"], 1),
            "finding_count": len(group["finding_ids"]),
            "asset_count": len(group["asset_ids"]),
            "external_asset_count": len(group["external_assets"]),
            "critical_asset_count": len(group["critical_assets"]),
            "oldest_age_days": round(group["oldest_age_days"], 1),
            "patch_refs": sorted(group["patch_refs"]),
            "hostnames": sorted(group["hostnames"]),
        })

    items.sort(key=lambda item: (
        -int(item["kev"]),
        -int(item["ransomware"]),
        -(item["max_epss"] or 0.0),
        -item["max_risk_score"],
        -item["asset_count"],
        item["cve"],
    ))
    items = items[:max(1, min(limit, 500))]
    return {
        "generated_at": reference.isoformat(),
        "epss_threshold": epss_threshold,
        "summary": {
            "cves": len(items),
            "kev": sum(1 for item in items if item["kev"]),
            "ransomware": sum(1 for item in items if item["ransomware"]),
            "affected_assets": len({
                hostname
                for item in items
                for hostname in item["hostnames"]
            }),
            "external_asset_exposures": sum(item["external_asset_count"] for item in items),
        },
        "items": items,
        "note": "Active Threat Watch is signal-based. It does not claim independent threat-research classification; it uses CISA KEV, EPSS and ransomware-use context available in the platform.",
    }



def normalize_patch_ref(value: Any) -> str:
    return str(value or "").strip()


def patch_ref_key(value: Any) -> str:
    return normalize_patch_ref(value).lower()


def patch_refs_from_scan_item(item: dict) -> list[str]:
    refs = []
    for value in item.get("kb") or []:
        ref = normalize_patch_ref(value)
        if ref:
            refs.append(ref)
    package = normalize_patch_ref(item.get("package"))
    if package:
        refs.append(package)
    if not refs:
        fallback = normalize_patch_ref(item.get("id"))
        if fallback:
            refs.append(fallback)
    return list(dict.fromkeys(refs))


def successful_patch_refs_for_agent(db: Session, agent_id: str) -> set[str]:
    refs = set()
    jobs = db.query(PatchJob).filter(
        PatchJob.agent_id == agent_id,
        PatchJob.action == "install_updates",
        PatchJob.status == "success",
    ).all()
    for job in jobs:
        payload = load(job.payload_json, {})
        for value in payload.get("packages", []) or []:
            key = patch_ref_key(value)
            if key:
                refs.add(key)
    return refs


def sync_patch_catalog_for_agent(db: Session, agent: Agent, patch_scan: list[dict]) -> dict:
    reference = now()
    observed_keys = set()
    created = 0
    updated = 0

    for item in patch_scan:
        if not isinstance(item, dict):
            continue
        refs = patch_refs_from_scan_item(item)
        for patch_ref in refs:
            key = patch_ref_key(patch_ref)
            if not key:
                continue
            observed_keys.add(key)
            entry = db.get(PatchCatalogEntry, key)
            metadata = {
                "id": item.get("id"),
                "kb": item.get("kb") or [],
                "package": item.get("package") or "",
                "raw_version": item.get("version") or "",
            }
            if not entry:
                entry = PatchCatalogEntry(
                    patch_key=key,
                    patch_ref=patch_ref,
                    vendor="Microsoft" if str(agent.os_family or "").lower() == "windows" else "",
                    product=agent.os_name or agent.os_family or "",
                    title=str(item.get("title") or ""),
                    severity=str(item.get("severity") or "unknown").lower(),
                    version=str(item.get("version") or ""),
                    reboot_behavior=str(item.get("reboot_behavior") or ""),
                    source="agent_scan",
                    metadata_json=dump(metadata),
                    first_seen=reference,
                    last_seen=reference,
                )
                db.add(entry)
                created += 1
            else:
                entry.patch_ref = patch_ref
                entry.title = str(item.get("title") or entry.title or "")
                entry.severity = str(item.get("severity") or entry.severity or "unknown").lower()
                entry.version = str(item.get("version") or entry.version or "")
                entry.reboot_behavior = str(item.get("reboot_behavior") or entry.reboot_behavior or "")
                entry.product = entry.product or agent.os_name or agent.os_family or ""
                entry.vendor = entry.vendor or ("Microsoft" if str(agent.os_family or "").lower() == "windows" else "")
                entry.metadata_json = dump(metadata)
                entry.last_seen = reference
                updated += 1

            obs = db.query(PatchApplicability).filter(
                PatchApplicability.patch_key == key,
                PatchApplicability.agent_id == agent.id,
            ).first()
            if not obs:
                obs = PatchApplicability(
                    id=str(uuid.uuid4()),
                    patch_key=key,
                    agent_id=agent.id,
                    status="missing",
                    evidence="agent_scan",
                    first_seen=reference,
                    last_seen=reference,
                    last_changed_at=reference,
                    details_json=dump({"hostname": agent.hostname}),
                )
                db.add(obs)
            else:
                if obs.status != "missing":
                    obs.last_changed_at = reference
                obs.status = "missing"
                obs.evidence = "agent_scan"
                obs.last_seen = reference
                obs.details_json = dump({"hostname": agent.hostname})

    previous = db.query(PatchApplicability).filter(
        PatchApplicability.agent_id == agent.id,
        PatchApplicability.status == "missing",
    ).all()
    successful_refs = successful_patch_refs_for_agent(db, agent.id)
    for obs in previous:
        if obs.patch_key in observed_keys:
            continue
        obs.status = "installed_inferred" if obs.patch_key in successful_refs else "no_longer_reported"
        obs.evidence = "successful_install_job" if obs.patch_key in successful_refs else "scan_delta"
        obs.last_changed_at = reference
        obs.last_seen = reference

    return {"catalog_created": created, "catalog_updated": updated, "observed": len(observed_keys)}



def second_tuesday(year: int, month: int) -> datetime:
    first = datetime(year, month, 1, tzinfo=timezone.utc)
    days_until_tuesday = (1 - first.weekday()) % 7
    return first + timedelta(days=days_until_tuesday + 7)



PATCH_METADATA_FIELDS = (
    "vendor",
    "product",
    "title",
    "severity",
    "classification",
    "release_date",
    "eol_date",
    "supersedes",
    "cves",
)


def normalize_metadata_value(field: str, value: Any):
    if field in {"release_date", "eol_date"}:
        if value is None or value == "":
            return None
        if isinstance(value, datetime):
            dt = value
        else:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    if field in {"supersedes", "cves"}:
        values = value or []
        normalized = []
        for item in values:
            raw = normalize_cve(item) if field == "cves" else normalize_patch_ref(item)
            if raw:
                normalized.append(raw)
        return list(dict.fromkeys(normalized))
    if value is None:
        return None
    return str(value).strip()


def metadata_value_for_json(value: Any):
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def patch_enrichment_state(entry: PatchCatalogEntry, reference: datetime | None = None) -> dict:
    reference = reference or now()
    state = load(entry.enrichment_json, {})
    fields = state.get("fields") if isinstance(state.get("fields"), dict) else {}
    conflicts = state.get("conflicts") if isinstance(state.get("conflicts"), list) else []
    stale = []
    for field, meta in fields.items():
        expires_at = meta.get("expires_at") if isinstance(meta, dict) else None
        if not expires_at:
            continue
        try:
            expires = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if expires <= reference:
                stale.append(field)
        except ValueError:
            continue
    return {
        "fields": fields,
        "conflicts": conflicts[-50:],
        "stale_fields": sorted(stale),
        "stale": bool(stale),
        "sources": sorted({
            str(meta.get("source"))
            for meta in fields.values()
            if isinstance(meta, dict) and meta.get("source")
        }),
    }


def current_entry_field(entry: PatchCatalogEntry, field: str):
    if field == "supersedes":
        return load(entry.supersedes_json, [])
    if field == "cves":
        state = load(entry.enrichment_json, {})
        return state.get("enriched_cves", []) if isinstance(state, dict) else []
    return getattr(entry, field)


def set_entry_field(entry: PatchCatalogEntry, field: str, value: Any):
    if field == "supersedes":
        entry.supersedes_json = dump(value or [])
    elif field == "cves":
        state = load(entry.enrichment_json, {})
        state["enriched_cves"] = value or []
        entry.enrichment_json = dump(state)
    else:
        setattr(entry, field, value)


def apply_patch_metadata_record(
    entry: PatchCatalogEntry,
    payload: dict,
    source: str,
    priority: int,
    observed_at: datetime,
    expires_at: datetime | None,
    actor: str,
    dry_run: bool = False,
) -> dict:
    state = load(entry.enrichment_json, {})
    fields = state.get("fields") if isinstance(state.get("fields"), dict) else {}
    conflicts = state.get("conflicts") if isinstance(state.get("conflicts"), list) else []
    changes = []
    rejected = []

    for field in PATCH_METADATA_FIELDS:
        if field not in payload:
            continue
        incoming = normalize_metadata_value(field, payload.get(field))
        if incoming in (None, "", []):
            continue
        current = current_entry_field(entry, field)
        current_meta = fields.get(field) if isinstance(fields.get(field), dict) else {}
        current_priority = int(current_meta.get("priority") or 0)
        current_observed_raw = current_meta.get("observed_at")
        try:
            current_observed = datetime.fromisoformat(str(current_observed_raw).replace("Z", "+00:00")) if current_observed_raw else None
        except ValueError:
            current_observed = None
        if current_observed is not None and current_observed.tzinfo is None:
            current_observed = current_observed.replace(tzinfo=timezone.utc)

        incoming_json = metadata_value_for_json(incoming)
        current_json = metadata_value_for_json(current)
        wins = (
            priority > current_priority
            or (
                priority == current_priority
                and (current_observed is None or observed_at >= current_observed)
            )
            or not current_meta
        )

        if not wins and incoming_json != current_json:
            conflict = {
                "field": field,
                "incoming": incoming_json,
                "current": current_json,
                "incoming_source": source,
                "current_source": current_meta.get("source", ""),
                "incoming_priority": priority,
                "current_priority": current_priority,
                "observed_at": observed_at.isoformat(),
            }
            conflicts.append(conflict)
            rejected.append(conflict)
            continue

        if incoming_json != current_json:
            changes.append({
                "field": field,
                "from": current_json,
                "to": incoming_json,
            })
        fields[field] = {
            "source": source,
            "priority": priority,
            "observed_at": observed_at.isoformat(),
            "expires_at": expires_at.isoformat() if expires_at else None,
            "actor": actor,
        }
        if not dry_run:
            if field == "cves":
                state["enriched_cves"] = incoming or []
            else:
                set_entry_field(entry, field, incoming)

    if not dry_run:
        state["fields"] = fields
        state["conflicts"] = conflicts[-100:]
        entry.enrichment_json = dump(state)
        entry.lifecycle_source = source
        entry.lifecycle_updated_by = actor
        entry.lifecycle_updated_at = observed_at

    return {"changes": changes, "rejected": rejected}


def import_patch_metadata(
    db: Session,
    body: PatchMetadataImportRequest,
    actor: str,
) -> dict:
    reference = body.observed_at or now()
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    expires_at = reference + timedelta(hours=body.ttl_hours) if body.ttl_hours else None
    source = body.source.strip().lower()
    stats = {
        "records": len(body.records),
        "matched": 0,
        "missing_catalog_entry": 0,
        "changed_fields": 0,
        "rejected_conflicts": 0,
        "dry_run": body.dry_run,
    }
    results = []

    for record in body.records:
        key = patch_ref_key(record.patch_ref)
        entry = db.get(PatchCatalogEntry, key)
        if not entry:
            stats["missing_catalog_entry"] += 1
            results.append({"patch_ref": record.patch_ref, "status": "missing_catalog_entry"})
            continue

        payload = record.model_dump(exclude_none=True)
        payload.pop("patch_ref", None)
        payload.pop("source_url", None)
        applied = apply_patch_metadata_record(
            entry,
            payload,
            source,
            body.priority,
            reference,
            expires_at,
            actor,
            dry_run=body.dry_run,
        )
        stats["matched"] += 1
        stats["changed_fields"] += len(applied["changes"])
        stats["rejected_conflicts"] += len(applied["rejected"])

        if not body.dry_run:
            evidence = db.query(PatchMetadataEvidence).filter(
                PatchMetadataEvidence.patch_key == key,
                PatchMetadataEvidence.source == source,
            ).first()
            evidence_payload = record.model_dump(mode="json", exclude_none=True)
            if evidence:
                evidence.priority = body.priority
                evidence.observed_at = reference
                evidence.expires_at = expires_at
                evidence.payload_json = dump(evidence_payload)
                evidence.imported_by = actor
            else:
                db.add(PatchMetadataEvidence(
                    id=str(uuid.uuid4()),
                    patch_key=key,
                    source=source,
                    priority=body.priority,
                    observed_at=reference,
                    expires_at=expires_at,
                    payload_json=dump(evidence_payload),
                    imported_by=actor,
                ))

        results.append({
            "patch_ref": record.patch_ref,
            "status": "applied" if applied["changes"] else "no_change",
            **applied,
        })

    if not body.dry_run:
        db.commit()
    return {
        "source": source,
        "priority": body.priority,
        "observed_at": reference.isoformat(),
        "expires_at": expires_at.isoformat() if expires_at else None,
        "summary": stats,
        "results": results[:500],
    }



PATCH_FEED_STOP = threading.Event()
PATCH_FEED_WAKE = threading.Event()
PATCH_FEED_SYNC_LOCK = threading.Lock()


def serialize_patch_feed_provider(provider: PatchFeedProvider, reference: datetime | None = None) -> dict:
    reference = reference or now()
    circuit = provider.circuit_open_until
    if circuit and circuit.tzinfo is None:
        circuit = circuit.replace(tzinfo=timezone.utc)
    circuit_open = bool(circuit and circuit > reference)
    return {
        "id": provider.id,
        "name": provider.name,
        "provider_type": provider.provider_type,
        "enabled": provider.enabled,
        "priority": provider.priority,
        "ttl_hours": provider.ttl_hours,
        "interval_seconds": provider.interval_seconds,
        "failure_threshold": provider.failure_threshold,
        "cooldown_seconds": provider.cooldown_seconds,
        "consecutive_failures": provider.consecutive_failures,
        "circuit_open": circuit_open,
        "circuit_open_until": circuit.isoformat() if circuit else None,
        "last_attempt_at": provider.last_attempt_at.isoformat() if provider.last_attempt_at else None,
        "last_success_at": provider.last_success_at.isoformat() if provider.last_success_at else None,
        "last_error": provider.last_error,
        "last_summary": load(provider.last_summary_json, {}),
        "record_count": len(load(provider.records_json, [])),
        "config": load(provider.provider_config_json, {}),
        "adapter_state": load(provider.adapter_state_json, {}),
        "created_by": provider.created_by,
        "updated_by": provider.updated_by,
        "created_at": provider.created_at.isoformat() if provider.created_at else None,
        "updated_at": provider.updated_at.isoformat() if provider.updated_at else None,
    }


def patch_feed_due(provider: PatchFeedProvider, reference: datetime | None = None) -> bool:
    reference = reference or now()
    if not provider.enabled:
        return False
    if provider.circuit_open_until:
        circuit = provider.circuit_open_until
        if circuit.tzinfo is None:
            circuit = circuit.replace(tzinfo=timezone.utc)
        if circuit > reference:
            return False
    if not provider.last_attempt_at:
        return True
    attempted = provider.last_attempt_at
    if attempted.tzinfo is None:
        attempted = attempted.replace(tzinfo=timezone.utc)
    return attempted + timedelta(seconds=provider.interval_seconds) <= reference


def run_patch_feed_provider(db: Session, provider: PatchFeedProvider, actor: str = "system:patch-feed") -> dict:
    reference = now()
    if provider.circuit_open_until:
        circuit = provider.circuit_open_until
        if circuit.tzinfo is None:
            circuit = circuit.replace(tzinfo=timezone.utc)
        if circuit > reference:
            return {
                "provider": provider.name,
                "status": "circuit_open",
                "circuit_open_until": circuit.isoformat(),
            }

    provider.last_attempt_at = reference
    provider.last_error = ""
    db.commit()

    try:
        if provider.provider_type == "curated":
            raw_records = load(provider.records_json, [])
            adapter_state = load(provider.adapter_state_json, {})
            adapter_meta = {"adapter": "curated", "records": len(raw_records)}
        else:
            adapter_result = fetch_patch_feed_records(
                provider.provider_type,
                config=load(provider.provider_config_json, {}),
                state=load(provider.adapter_state_json, {}),
            )
            raw_records = adapter_result["records"]
            adapter_state = adapter_result.get("state", {})
            adapter_meta = adapter_result.get("meta", {})

        body = PatchMetadataImportRequest(
            source=f"feed:{provider.name}",
            priority=provider.priority,
            observed_at=reference,
            ttl_hours=provider.ttl_hours,
            dry_run=False,
            records=raw_records,
        )
        result = import_patch_metadata(db, body, actor)
        summary = result["summary"]
        provider.last_success_at = reference
        provider.last_error = ""
        provider.consecutive_failures = 0
        provider.circuit_open_until = None
        provider.adapter_state_json = dump(adapter_state)
        provider.last_summary_json = dump({**summary, "adapter": adapter_meta})
        db.commit()
        return {
            "provider": provider.name,
            "status": "ok",
            "summary": summary,
            "adapter": adapter_meta,
        }
    except Exception as exc:
        provider.consecutive_failures = int(provider.consecutive_failures or 0) + 1
        provider.last_error = str(exc)[:2000]
        if provider.consecutive_failures >= provider.failure_threshold:
            provider.circuit_open_until = reference + timedelta(seconds=provider.cooldown_seconds)
        provider.last_summary_json = dump({
            "error": provider.last_error,
            "consecutive_failures": provider.consecutive_failures,
        })
        db.commit()
        raise


def patch_feed_orchestrator_report(db: Session) -> dict:
    reference = now()
    providers = db.query(PatchFeedProvider).order_by(PatchFeedProvider.name.asc()).all()
    items = [serialize_patch_feed_provider(item, reference) for item in providers]
    return {
        "generated_at": reference.isoformat(),
        "summary": {
            "providers": len(items),
            "enabled": sum(1 for x in items if x["enabled"]),
            "healthy": sum(1 for x in items if x["enabled"] and not x["circuit_open"] and not x["last_error"]),
            "degraded": sum(1 for x in items if x["enabled"] and bool(x["last_error"]) and not x["circuit_open"]),
            "circuit_open": sum(1 for x in items if x["circuit_open"]),
            "records": sum(int(x["record_count"] or 0) for x in items),
        },
        "providers": items,
    }


def patch_feed_worker():
    while not PATCH_FEED_STOP.is_set():
        db = SessionLocal()
        try:
            due = db.query(PatchFeedProvider).filter(PatchFeedProvider.enabled.is_(True)).all()
            for provider in due:
                if PATCH_FEED_STOP.is_set():
                    break
                if not patch_feed_due(provider):
                    continue
                try:
                    with PATCH_FEED_SYNC_LOCK:
                        run_patch_feed_provider(db, provider)
                except Exception:
                    pass
        finally:
            db.close()
        PATCH_FEED_WAKE.wait(30)
        PATCH_FEED_WAKE.clear()


@app.on_event("startup")
def start_patch_feed_worker():
    thread = threading.Thread(target=patch_feed_worker, name="patch-feed-orchestrator", daemon=True)
    thread.start()


@app.on_event("shutdown")
def stop_patch_feed_worker():
    PATCH_FEED_STOP.set()
    PATCH_FEED_WAKE.set()


def patch_release_intelligence(entry: PatchCatalogEntry, reference: datetime | None = None) -> dict:
    reference = reference or now()
    released = entry.release_date
    if released is not None and released.tzinfo is None:
        released = released.replace(tzinfo=timezone.utc)
    eol = entry.eol_date
    if eol is not None and eol.tzinfo is None:
        eol = eol.replace(tzinfo=timezone.utc)

    release_age_days = max(0, (reference - released).days) if released else None
    eol_state = "unknown"
    days_to_eol = None
    if eol:
        days_to_eol = (eol - reference).days
        if days_to_eol < 0:
            eol_state = "eol"
        elif days_to_eol <= 90:
            eol_state = "eol_soon"
        else:
            eol_state = "supported"

    patch_tuesday = False
    patch_tuesday_delta_days = None
    if released:
        expected = second_tuesday(released.year, released.month)
        patch_tuesday_delta_days = abs((released.date() - expected.date()).days)
        patch_tuesday = patch_tuesday_delta_days <= 1

    return {
        "release_date": released.isoformat() if released else None,
        "release_age_days": release_age_days,
        "patch_tuesday": patch_tuesday,
        "patch_tuesday_delta_days": patch_tuesday_delta_days,
        "eol_date": eol.isoformat() if eol else None,
        "eol_state": eol_state,
        "days_to_eol": days_to_eol,
        "classification": entry.classification or "",
        "lifecycle_source": entry.lifecycle_source or "",
        "lifecycle_updated_by": entry.lifecycle_updated_by or "",
        "lifecycle_updated_at": entry.lifecycle_updated_at.isoformat() if entry.lifecycle_updated_at else None,
    }


def patch_supersedence_graph(entries: list[PatchCatalogEntry]) -> dict:
    by_key = {entry.patch_key: entry for entry in entries}
    supersedes = {}
    superseded_by = {}
    for entry in entries:
        targets = []
        for ref in load(entry.supersedes_json, []):
            key = patch_ref_key(ref)
            if key and key != entry.patch_key:
                targets.append(key)
                superseded_by.setdefault(key, set()).add(entry.patch_key)
        supersedes[entry.patch_key] = sorted(set(targets))

    def descendants(start: str, limit: int = 50) -> list[str]:
        seen = set()
        stack = list(supersedes.get(start, []))
        ordered = []
        while stack and len(ordered) < limit:
            key = stack.pop(0)
            if key in seen:
                continue
            seen.add(key)
            ordered.append(key)
            stack.extend(supersedes.get(key, []))
        return ordered

    def replacers(start: str, limit: int = 50) -> list[str]:
        seen = set()
        queue = sorted(superseded_by.get(start, set()))
        ordered = []
        while queue and len(ordered) < limit:
            key = queue.pop(0)
            if key in seen:
                continue
            seen.add(key)
            ordered.append(key)
            queue.extend(sorted(superseded_by.get(key, set())))
        return ordered

    graph = {}
    for key in by_key:
        replacing = replacers(key)
        leaves = [
            candidate for candidate in replacing
            if not superseded_by.get(candidate)
        ]
        graph[key] = {
            "supersedes_keys": supersedes.get(key, []),
            "supersedes_all_keys": descendants(key),
            "superseded_by_keys": sorted(superseded_by.get(key, set())),
            "replacement_chain_keys": replacing,
            "leaf_replacement_keys": leaves,
            "obsolete": bool(superseded_by.get(key)),
        }
    return graph


def choose_preferred_replacement(
    entry: PatchCatalogEntry,
    graph_item: dict,
    entries_by_key: dict[str, PatchCatalogEntry],
) -> PatchCatalogEntry | None:
    candidates = [
        entries_by_key[key]
        for key in graph_item.get("leaf_replacement_keys", [])
        if key in entries_by_key
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda candidate: (
        candidate.release_date or datetime.min.replace(tzinfo=timezone.utc),
        candidate.last_seen or datetime.min.replace(tzinfo=timezone.utc),
        candidate.patch_ref.lower(),
    ), reverse=True)
    return candidates[0]


def patch_catalog_report(db: Session, limit: int = 500) -> dict:
    reference = now()
    confidence_map = {
        item["patch_ref"].lower(): item
        for item in patch_confidence_report(db, limit=1000)["items"]
    }
    active_rules = active_patch_block_rules(db, reference)
    findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.status == "open").all()
    by_patch = {}
    for finding in findings:
        for ref in load(finding.patch_refs_json, []):
            key = patch_ref_key(ref)
            if not key:
                continue
            bucket = by_patch.setdefault(key, {"cves": set(), "finding_count": 0, "kev": 0, "ransomware": 0})
            bucket["finding_count"] += 1
            if finding.cve:
                bucket["cves"].add(finding.cve)
            risk = finding_detection_risk(finding, reference)
            bucket["kev"] += 1 if risk["kev"] else 0
            bucket["ransomware"] += 1 if risk["ransomware"] else 0

    entries = db.query(PatchCatalogEntry).options(
        selectinload(PatchCatalogEntry.observations).selectinload(PatchApplicability.agent)
    ).order_by(PatchCatalogEntry.last_seen.desc()).all()
    graph = patch_supersedence_graph(entries)
    entries_by_key = {entry.patch_key: entry for entry in entries}
    items = []
    for entry in entries:
        observations = entry.observations or []
        counts = {
            "missing": sum(1 for x in observations if x.status == "missing"),
            "installed_inferred": sum(1 for x in observations if x.status == "installed_inferred"),
            "no_longer_reported": sum(1 for x in observations if x.status == "no_longer_reported"),
        }
        affected = [
            {
                "agent_id": x.agent_id,
                "hostname": x.agent.hostname if x.agent else "",
                "status": x.status,
                "evidence": x.evidence,
                "last_seen": x.last_seen.isoformat() if x.last_seen else None,
            }
            for x in observations
            if x.status == "missing"
        ][:50]
        blocking_rules = [
            serialize_patch_block_rule(rule, reference)
            for rule in active_rules
            if str(rule.patch_ref or "").strip().lower() == entry.patch_key
        ]
        confidence = confidence_map.get(entry.patch_key)
        threat = by_patch.get(entry.patch_key, {"cves": set(), "finding_count": 0, "kev": 0, "ransomware": 0})
        enrichment = patch_enrichment_state(entry, reference)
        enriched_cves = set(load(entry.enrichment_json, {}).get("enriched_cves", []))
        threat["cves"] = set(threat["cves"]) | enriched_cves

        graph_item = graph.get(entry.patch_key, {})
        preferred_replacement = choose_preferred_replacement(entry, graph_item, entries_by_key)
        lifecycle = patch_release_intelligence(entry, reference)
        if blocking_rules:
            readiness = "blocked"
            readiness_reasons = ["Patch Guard ativo"]
        elif lifecycle["eol_state"] == "eol":
            readiness = "review"
            readiness_reasons = ["produto/patch marcada como EOL; validar caminho suportado"]
        elif graph_item.get("obsolete") and preferred_replacement:
            readiness = "superseded"
            readiness_reasons = [f"superseded por {preferred_replacement.patch_ref}; preferir patch leaf"]
        elif counts["missing"] == 0:
            readiness = "not_applicable"
            readiness_reasons = ["nenhum endpoint reporta a patch como pendente"]
        elif confidence and confidence["confidence"] == "high":
            readiness = "ready"
            readiness_reasons = ["alta confiança local de deployment"]
        elif confidence and confidence["confidence"] == "medium":
            readiness = "ready_with_controls"
            readiness_reasons = ["confiança local média; usar rollout progressivo e health gate"]
        elif confidence and confidence["confidence"] == "low":
            readiness = "review"
            readiness_reasons = ["baixa confiança local; revisar falhas antes de ampliar"]
        else:
            readiness = "pilot"
            readiness_reasons = ["sem histórico local suficiente; iniciar piloto controlado"]

        if threat["kev"]:
            readiness_reasons.append(f'{threat["kev"]} finding(s) KEV')
        if threat["ransomware"]:
            readiness_reasons.append(f'{threat["ransomware"]} finding(s) com ransomware known')

        items.append({
            "patch_ref": entry.patch_ref,
            "patch_key": entry.patch_key,
            "vendor": entry.vendor,
            "product": entry.product,
            "title": entry.title,
            "severity": entry.severity,
            "version": entry.version,
            "reboot_behavior": entry.reboot_behavior,
            "source": entry.source,
            "enrichment": enrichment,
            "lifecycle": lifecycle,
            "supersedence": {
                "supersedes": [
                    entries_by_key[key].patch_ref if key in entries_by_key else key
                    for key in graph_item.get("supersedes_keys", [])
                ],
                "superseded_by": [
                    entries_by_key[key].patch_ref if key in entries_by_key else key
                    for key in graph_item.get("superseded_by_keys", [])
                ],
                "replacement_chain": [
                    entries_by_key[key].patch_ref if key in entries_by_key else key
                    for key in graph_item.get("replacement_chain_keys", [])
                ],
                "obsolete": bool(graph_item.get("obsolete")),
                "preferred_replacement": preferred_replacement.patch_ref if preferred_replacement else None,
            },
            "first_seen": entry.first_seen.isoformat() if entry.first_seen else None,
            "last_seen": entry.last_seen.isoformat() if entry.last_seen else None,
            "states": counts,
            "affected_assets": affected,
            "patch_confidence": confidence,
            "guard": {
                "blocked": bool(blocking_rules),
                "rules": blocking_rules,
            },
            "threat": {
                "cves": sorted(threat["cves"]),
                "finding_count": threat["finding_count"],
                "kev_findings": threat["kev"],
                "ransomware_findings": threat["ransomware"],
            },
            "deployment_readiness": {
                "status": readiness,
                "reasons": readiness_reasons,
            },
        })

    rank = {"blocked": 0, "review": 1, "superseded": 2, "pilot": 3, "ready_with_controls": 4, "ready": 5, "not_applicable": 6}
    items.sort(key=lambda x: (
        rank.get(x["deployment_readiness"]["status"], 9),
        -x["threat"]["kev_findings"],
        -x["states"]["missing"],
        x["patch_ref"].lower(),
    ))
    items = items[:max(1, min(limit, 2000))]
    return {
        "generated_at": reference.isoformat(),
        "summary": {
            "patches": len(items),
            "missing_observations": sum(x["states"]["missing"] for x in items),
            "installed_inferred": sum(x["states"]["installed_inferred"] for x in items),
            "blocked": sum(1 for x in items if x["deployment_readiness"]["status"] == "blocked"),
            "superseded": sum(1 for x in items if x["deployment_readiness"]["status"] == "superseded"),
            "eol": sum(1 for x in items if x["lifecycle"]["eol_state"] == "eol"),
            "patch_tuesday": sum(1 for x in items if x["lifecycle"]["patch_tuesday"]),
            "stale_metadata": sum(1 for x in items if x["enrichment"]["stale"]),
            "metadata_conflicts": sum(len(x["enrichment"]["conflicts"]) for x in items),
            "ready": sum(1 for x in items if x["deployment_readiness"]["status"] == "ready"),
            "pilot": sum(1 for x in items if x["deployment_readiness"]["status"] == "pilot"),
        },
        "items": items,
        "note": "Installed is inferred only when a previously missing patch disappears after a successful targeted install job. Other disappearances remain no_longer_reported.",
    }


def patch_confidence_report(
    db: Session,
    limit: int = 200,
) -> dict:
    campaigns = db.query(Campaign).options(
        selectinload(Campaign.jobs),
    ).filter(
        Campaign.action == "install_updates",
    ).all()
    buckets: dict[str, dict] = {}

    for campaign in campaigns:
        payload = load(campaign.payload_json, {})
        packages = sorted({
            str(package).strip()
            for package in payload.get("packages", [])
            if str(package).strip()
        })
        if not packages:
            continue

        for package in packages:
            bucket = buckets.setdefault(package.lower(), {
                "patch_ref": package,
                "success": 0,
                "failed": 0,
                "stalled": 0,
                "blocked": 0,
                "other": 0,
                "campaign_ids": set(),
                "agent_ids": set(),
                "last_execution_at": None,
            })
            bucket["campaign_ids"].add(campaign.id)
            for job in campaign.jobs or []:
                bucket["agent_ids"].add(job.agent_id)
                if job.status == "success":
                    bucket["success"] += 1
                elif job.status == "failed":
                    bucket["failed"] += 1
                elif job.status == "stalled":
                    bucket["stalled"] += 1
                elif job.status == "blocked":
                    bucket["blocked"] += 1
                elif job.status not in {"pending", "claimed", "running"}:
                    bucket["other"] += 1
                executed_at = job.finished_at or job.started_at or job.created_at
                if executed_at and executed_at.tzinfo is None:
                    executed_at = executed_at.replace(tzinfo=timezone.utc)
                if executed_at and (
                    bucket["last_execution_at"] is None
                    or executed_at > bucket["last_execution_at"]
                ):
                    bucket["last_execution_at"] = executed_at

    items = []
    for bucket in buckets.values():
        completed = bucket["success"] + bucket["failed"]
        success_rate = (
            round(bucket["success"] / completed * 100.0, 1)
            if completed
            else None
        )
        if completed < 5:
            confidence = "insufficient_data"
        elif success_rate is not None and success_rate >= 95.0 and completed >= 10:
            confidence = "high"
        elif success_rate is not None and success_rate >= 80.0:
            confidence = "medium"
        else:
            confidence = "low"

        items.append({
            "patch_ref": bucket["patch_ref"],
            "confidence": confidence,
            "completed_jobs": completed,
            "success": bucket["success"],
            "failed": bucket["failed"],
            "stalled": bucket["stalled"],
            "blocked": bucket["blocked"],
            "success_rate": success_rate,
            "campaign_count": len(bucket["campaign_ids"]),
            "asset_count": len(bucket["agent_ids"]),
            "last_execution_at": (
                bucket["last_execution_at"].isoformat()
                if bucket["last_execution_at"]
                else None
            ),
        })

    confidence_rank = {"high": 0, "medium": 1, "low": 2, "insufficient_data": 3}
    items.sort(key=lambda item: (
        confidence_rank[item["confidence"]],
        -(item["completed_jobs"]),
        item["patch_ref"].lower(),
    ))
    items = items[:max(1, min(limit, 1000))]
    return {
        "generated_at": now().isoformat(),
        "summary": {
            "patches_observed": len(items),
            "high_confidence": sum(1 for item in items if item["confidence"] == "high"),
            "low_confidence": sum(1 for item in items if item["confidence"] == "low"),
            "insufficient_data": sum(1 for item in items if item["confidence"] == "insufficient_data"),
        },
        "items": items,
        "note": "Patch Confidence uses this environment's own completed deployment history. Bundle jobs are attributed to each package in that bundle and should be interpreted as local operational evidence, not vendor-wide reliability telemetry.",
    }


def _finding_has_patch_ref(finding: VulnerabilityFinding, patch_ref: str) -> bool:
    target = str(patch_ref or "").strip().lower()
    if not target:
        return False
    return any(
        str(ref).strip().lower() == target
        for ref in load(finding.patch_refs_json, [])
        if str(ref).strip()
    )


def _remediation_project_open_findings(
    db: Session,
    patch_ref: str,
    scope_tag: str = "",
    scope_filter: dict | None = None,
) -> list[VulnerabilityFinding]:
    tag = str(scope_tag or "").strip().lower()
    scope_filter = scope_filter if isinstance(scope_filter, dict) else {}
    business_service = str(scope_filter.get("business_service") or "").strip().lower()
    environment = str(scope_filter.get("environment") or "").strip().lower()
    asset_owner = str(scope_filter.get("owner") or "").strip().lower()
    external_filter = scope_filter.get("external")
    min_criticality = scope_filter.get("min_criticality")
    findings = db.query(VulnerabilityFinding).options(
        selectinload(VulnerabilityFinding.agent).selectinload(Agent.risk_profile),
        selectinload(VulnerabilityFinding.agent).selectinload(Agent.vulnerabilities),
    ).filter(
        VulnerabilityFinding.status == "open",
    ).all()
    items = []
    for finding in findings:
        if not _finding_has_patch_ref(finding, patch_ref):
            continue
        if tag:
            if not finding.agent:
                continue
            tags = {
                str(value).strip().lower()
                for value in load(finding.agent.tags, [])
                if str(value).strip()
            }
            if tag not in tags:
                continue

        if business_service or environment or asset_owner or external_filter is not None or min_criticality is not None:
            agent = finding.agent
            if not agent:
                continue
            profile = agent.risk_profile
            if business_service:
                current = str(profile.business_service if profile else "").strip().lower()
                if current != business_service:
                    continue
            if environment:
                current = str(profile.environment if profile else "").strip().lower()
                if current != environment:
                    continue
            if asset_owner:
                current = str(profile.owner if profile else "").strip().lower()
                if current != asset_owner:
                    continue
            if external_filter is not None:
                if bool(asset_exposure(agent).get("external")) is not bool(external_filter):
                    continue
            if min_criticality is not None:
                try:
                    minimum = int(min_criticality)
                except (TypeError, ValueError):
                    minimum = 1
                if int(asset_criticality(agent).get("score") or 0) < minimum:
                    continue
        items.append(finding)
    return items


def _remediation_project_risk_reduction(
    findings: list[VulnerabilityFinding],
    reference: datetime | None = None,
) -> float:
    reference = reference or now()
    by_agent: dict[str, list[VulnerabilityFinding]] = {}
    for finding in findings:
        if finding.agent_id and finding.agent:
            by_agent.setdefault(finding.agent_id, []).append(finding)

    reduction = 0.0
    for project_findings in by_agent.values():
        agent = project_findings[0].agent
        all_open = [
            finding
            for finding in (agent.vulnerabilities or [])
            if finding.status == "open"
        ]
        excluded = {finding.id for finding in project_findings}
        after_findings = [
            finding for finding in all_open
            if finding.id not in excluded
        ]
        before = asset_risk_score(agent, all_open, reference)
        after = asset_risk_score(agent, after_findings, reference)
        reduction += max(0.0, before["score"] - after["score"])
    return round(reduction, 1)


def serialize_remediation_project(
    db: Session,
    project: RemediationProject,
    reference: datetime | None = None,
) -> dict:
    reference = reference or now()
    snapshot = load(project.scope_snapshot_json, {})
    baseline_ids = {
        str(value)
        for value in snapshot.get("finding_ids", [])
        if str(value)
    }

    baseline_rows = (
        db.query(VulnerabilityFinding).options(
            selectinload(VulnerabilityFinding.agent).selectinload(Agent.risk_profile),
            selectinload(VulnerabilityFinding.agent).selectinload(Agent.vulnerabilities),
        ).filter(
            VulnerabilityFinding.id.in_(baseline_ids)
        ).all()
        if baseline_ids
        else []
    )
    baseline_open_ids = {
        finding.id
        for finding in baseline_rows
        if finding.status == "open"
    }

    if project.scope_mode == "dynamic":
        open_findings = _remediation_project_open_findings(
            db,
            project.patch_ref,
            project.scope_tag,
            load(project.scope_filter_json, {}),
        )
        current_open_ids = {finding.id for finding in open_findings}
        current_agent_ids = {
            finding.agent_id
            for finding in open_findings
            if finding.agent_id
        }
        new_findings = current_open_ids - baseline_ids
        scope_departures = baseline_open_ids - current_open_ids
    else:
        open_findings = [
            finding for finding in baseline_rows
            if finding.status == "open"
        ]
        current_open_ids = {finding.id for finding in open_findings}
        current_agent_ids = {
            finding.agent_id
            for finding in open_findings
            if finding.agent_id
        }
        new_findings = set()
        scope_departures = set()

    baseline_count = int(project.baseline_findings or 0)
    current_count = len(current_open_ids)
    closed_from_baseline = max(0, baseline_count - len(baseline_open_ids))
    tracked_open_count = len(baseline_open_ids) + len(new_findings)
    progress = (
        max(0.0, min(100.0, ((baseline_count - tracked_open_count) / baseline_count) * 100.0))
        if baseline_count > 0
        else 100.0
    )

    remaining_risk_reduction = _remediation_project_risk_reduction(open_findings, reference)
    baseline_risk_reduction = round(float(project.baseline_risk_reduction or 0.0), 1)
    realized_risk_reduction = round(
        max(0.0, baseline_risk_reduction - remaining_risk_reduction),
        1,
    )
    risk_reduction_progress_percent = (
        round(
            max(
                0.0,
                min(100.0, (realized_risk_reduction / baseline_risk_reduction) * 100.0),
            ),
            1,
        )
        if baseline_risk_reduction > 0
        else (100.0 if tracked_open_count == 0 else 0.0)
    )

    age_days = []
    kev_findings = 0
    sla_breached = 0
    sla_due_soon = 0
    sla_exception = 0
    epss_values = []
    external_agent_ids = set()
    business_services = set()
    business_owners = set()

    for finding in open_findings:
        first_seen = finding.first_seen
        if first_seen:
            if first_seen.tzinfo is None:
                first_seen = first_seen.replace(tzinfo=timezone.utc)
            age_days.append(max(0.0, (reference - first_seen).total_seconds() / 86400.0))

        risk = finding_detection_risk(finding, reference)
        if risk.get("kev"):
            kev_findings += 1
        epss = risk.get("epss")
        if epss is not None:
            epss_values.append(float(epss))

        sla = vulnerability_sla(finding, reference)
        if sla.get("state") == "breached":
            sla_breached += 1
        elif sla.get("state") == "due_soon":
            sla_due_soon += 1
        elif sla.get("state") == "exception":
            sla_exception += 1

        agent = finding.agent
        if agent:
            if asset_exposure(agent).get("external"):
                external_agent_ids.add(agent.id)
            profile = agent.risk_profile
            if profile:
                if str(profile.business_service or "").strip():
                    business_services.add(str(profile.business_service).strip())
                if str(profile.owner or "").strip():
                    business_owners.add(str(profile.owner).strip())

    average_age_days = round(sum(age_days) / len(age_days), 1) if age_days else 0.0
    oldest_age_days = round(max(age_days), 1) if age_days else 0.0
    average_epss = round(sum(epss_values) / len(epss_values), 4) if epss_values else None
    max_epss = round(max(epss_values), 4) if epss_values else None

    due_at = project.due_at
    if due_at.tzinfo is None:
        due_at = due_at.replace(tzinfo=timezone.utc)
    created_at = project.created_at
    if created_at and created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    schedule_duration = max(1.0, (due_at - created_at).total_seconds()) if created_at else 1.0
    elapsed = max(0.0, (reference - created_at).total_seconds()) if created_at else 0.0
    expected_progress_percent = round(
        max(0.0, min(100.0, (elapsed / schedule_duration) * 100.0)),
        1,
    )
    schedule_variance_percent = round(progress - expected_progress_percent, 1)

    achieved = tracked_open_count == 0
    if project.status == "completed":
        pace_status = "completed"
    elif project.status == "cancelled":
        pace_status = "cancelled"
    elif achieved:
        pace_status = "achieved"
    elif reference > due_at:
        pace_status = "overdue"
    elif project.status == "awaiting_verification":
        pace_status = "awaiting_verification"
    else:
        pace_status = "in_progress"

    if project.status == "completed":
        attention_status = "completed"
    elif project.status == "cancelled":
        attention_status = "cancelled"
    elif pace_status == "overdue":
        attention_status = "critical"
    elif sla_breached > 0 or (kev_findings > 0 and len(external_agent_ids) > 0):
        attention_status = "critical"
    elif schedule_variance_percent <= -20.0 or len(new_findings) > 0:
        attention_status = "needs_attention"
    elif schedule_variance_percent <= -10.0 or kev_findings > 0 or sla_due_soon > 0:
        attention_status = "watch"
    else:
        attention_status = "on_track"

    return {
        "id": project.id,
        "name": project.name,
        "patch_ref": project.patch_ref,
        "scope_mode": project.scope_mode,
        "scope_tag": project.scope_tag,
        "scope_filter": load(project.scope_filter_json, {}),
        "owner": project.owner,
        "due_at": due_at.isoformat(),
        "status": project.status,
        "pace_status": pace_status,
        "achieved": achieved,
        "baseline_findings": baseline_count,
        "baseline_assets": int(project.baseline_assets or 0),
        "baseline_risk_reduction": baseline_risk_reduction,
        "remaining_risk_reduction": remaining_risk_reduction,
        "realized_risk_reduction": realized_risk_reduction,
        "risk_reduction_progress_percent": risk_reduction_progress_percent,
        "current_open_findings": current_count,
        "tracked_open_findings": tracked_open_count,
        "current_assets": len(current_agent_ids),
        "closed_from_baseline": closed_from_baseline,
        "baseline_open_findings": len(baseline_open_ids),
        "scope_departures": len(scope_departures),
        "new_findings_since_baseline": len(new_findings),
        "progress_percent": round(progress, 1),
        "expected_progress_percent": expected_progress_percent,
        "schedule_variance_percent": schedule_variance_percent,
        "attention_status": attention_status,
        "sla_breached": sla_breached,
        "sla_due_soon": sla_due_soon,
        "sla_exception": sla_exception,
        "kev_findings": kev_findings,
        "external_assets": len(external_agent_ids),
        "average_age_days": average_age_days,
        "oldest_age_days": oldest_age_days,
        "average_epss": average_epss,
        "max_epss": max_epss,
        "business_services": sorted(business_services),
        "business_owners": sorted(business_owners),
        "campaign_ready": 0 < len(current_agent_ids) <= 500,
        "current_agent_ids": sorted(current_agent_ids) if len(current_agent_ids) <= 500 else [],
        "current_finding_ids": sorted(current_open_ids) if len(current_open_ids) <= 1000 else [],
        "reason": project.reason,
        "created_by": project.created_by,
        "updated_by": project.updated_by,
        "completed_at": project.completed_at.isoformat() if project.completed_at else None,
        "created_at": project.created_at.isoformat() if project.created_at else None,
        "updated_at": project.updated_at.isoformat() if project.updated_at else None,
    }


def capture_remediation_project_snapshots(
    db: Session,
    source: str,
    reference: datetime | None = None,
    minimum_interval_seconds: int = 3600,
    project_ids: set[str] | None = None,
) -> dict:
    reference = reference or now()
    query = db.query(RemediationProject).filter(
        RemediationProject.status.in_(["active", "awaiting_verification"])
    )
    if project_ids:
        query = query.filter(RemediationProject.id.in_(project_ids))
    projects = query.all()
    created = 0
    skipped = 0
    for project in projects:
        latest = db.query(RemediationProjectSnapshot).filter(
            RemediationProjectSnapshot.project_id == project.id
        ).order_by(RemediationProjectSnapshot.captured_at.desc()).first()
        if latest and minimum_interval_seconds > 0:
            captured = latest.captured_at
            if captured.tzinfo is None:
                captured = captured.replace(tzinfo=timezone.utc)
            if (reference - captured).total_seconds() < minimum_interval_seconds:
                skipped += 1
                continue
        data = serialize_remediation_project(db, project, reference)
        db.add(RemediationProjectSnapshot(
            project_id=project.id,
            tracked_open_findings=data["tracked_open_findings"],
            current_scope_findings=data["current_open_findings"],
            current_assets=data["current_assets"],
            closed_from_baseline=data["closed_from_baseline"],
            new_findings_since_baseline=data["new_findings_since_baseline"],
            scope_departures=data["scope_departures"],
            progress_percent=data["progress_percent"],
            remaining_risk_reduction=data["remaining_risk_reduction"],
            realized_risk_reduction=data["realized_risk_reduction"],
            risk_reduction_progress_percent=data["risk_reduction_progress_percent"],
            expected_progress_percent=data["expected_progress_percent"],
            schedule_variance_percent=data["schedule_variance_percent"],
            sla_breached=data["sla_breached"],
            kev_findings=data["kev_findings"],
            external_assets=data["external_assets"],
            average_age_days=data["average_age_days"],
            oldest_age_days=data["oldest_age_days"],
            attention_status=data["attention_status"],
            pace_status=data["pace_status"],
            source=source,
            captured_at=reference,
        ))
        created += 1
    db.commit()
    return {
        "created": created,
        "skipped": skipped,
        "source": source,
        "captured_at": reference.isoformat(),
    }


def remediation_project_history(
    db: Session,
    project_id: str,
    limit: int = 200,
) -> dict:
    project = db.get(RemediationProject, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="remediation project not found")
    rows = db.query(RemediationProjectSnapshot).filter(
        RemediationProjectSnapshot.project_id == project_id
    ).order_by(RemediationProjectSnapshot.captured_at.desc()).limit(
        max(1, min(limit, 1000))
    ).all()
    return {
        "project_id": project_id,
        "project_name": project.name,
        "items": [{
            "tracked_open_findings": row.tracked_open_findings,
            "current_scope_findings": row.current_scope_findings,
            "current_assets": row.current_assets,
            "closed_from_baseline": row.closed_from_baseline,
            "new_findings_since_baseline": row.new_findings_since_baseline,
            "scope_departures": row.scope_departures,
            "progress_percent": row.progress_percent,
            "remaining_risk_reduction": row.remaining_risk_reduction,
            "realized_risk_reduction": row.realized_risk_reduction,
            "risk_reduction_progress_percent": row.risk_reduction_progress_percent,
            "expected_progress_percent": row.expected_progress_percent,
            "schedule_variance_percent": row.schedule_variance_percent,
            "sla_breached": row.sla_breached,
            "kev_findings": row.kev_findings,
            "external_assets": row.external_assets,
            "average_age_days": row.average_age_days,
            "oldest_age_days": row.oldest_age_days,
            "attention_status": row.attention_status,
            "pace_status": row.pace_status,
            "source": row.source,
            "captured_at": row.captured_at.isoformat() if row.captured_at else None,
        } for row in rows],
    }


def remediation_projects_report(
    db: Session,
    reference: datetime | None = None,
) -> dict:
    reference = reference or now()
    projects = db.query(RemediationProject).order_by(
        RemediationProject.status.asc(),
        RemediationProject.due_at.asc(),
        RemediationProject.name.asc(),
    ).all()
    items = [
        serialize_remediation_project(db, project, reference)
        for project in projects
    ]
    return {
        "generated_at": reference.isoformat(),
        "summary": {
            "total": len(items),
            "active": sum(1 for item in items if item["status"] in {"active", "awaiting_verification"}),
            "awaiting_verification": sum(1 for item in items if item["status"] == "awaiting_verification"),
            "achieved": sum(1 for item in items if item["pace_status"] in {"achieved", "completed"}),
            "overdue": sum(1 for item in items if item["pace_status"] == "overdue"),
            "open_findings": sum(
                item["tracked_open_findings"]
                for item in items
                if item["status"] in {"active", "awaiting_verification"}
            ),
            "critical_attention": sum(
                1 for item in items
                if item["attention_status"] == "critical"
            ),
            "needs_attention": sum(
                1 for item in items
                if item["attention_status"] == "needs_attention"
            ),
            "kev_findings": sum(
                item["kev_findings"]
                for item in items
                if item["status"] in {"active", "awaiting_verification"}
            ),
            "sla_breached": sum(
                item["sla_breached"]
                for item in items
                if item["status"] in {"active", "awaiting_verification"}
            ),
            "remaining_risk_reduction": round(sum(
                item["remaining_risk_reduction"]
                for item in items
                if item["status"] in {"active", "awaiting_verification"}
            ), 1),
            "realized_risk_reduction": round(sum(
                item["realized_risk_reduction"]
                for item in items
            ), 1),
        },
        "items": items,
        "note": "Projects govern remediation work. They do not deploy patches or mutate vulnerability evidence.",
    }



REMEDIATION_PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}


def remediation_group_decision(
    *,
    kev_findings: int,
    ransomware_findings: int,
    high_epss_findings: int,
    max_epss: float,
    sla_breached: int,
    sla_due_soon: int,
    external_assets: int,
    critical_assets: int,
    asset_count: int,
    patch_confidence: dict | None,
) -> dict:
    """Build an explainable remediation priority and a conservative rollout plan."""
    priority_reasons = []
    confidence = (
        str((patch_confidence or {}).get("confidence") or "insufficient_data").strip().lower()
    )

    if kev_findings:
        priority_reasons.append(f"{kev_findings} finding(s) no CISA KEV")
    if ransomware_findings:
        priority_reasons.append(f"{ransomware_findings} finding(s) com uso conhecido em ransomware")
    if sla_breached:
        priority_reasons.append(f"{sla_breached} finding(s) com SLA vencido")
    if sla_due_soon:
        priority_reasons.append(f"{sla_due_soon} finding(s) próximos do SLA")
    if external_assets:
        priority_reasons.append(f"{external_assets} ativo(s) com exposição externa")
    if critical_assets:
        priority_reasons.append(f"{critical_assets} ativo(s) de criticidade 4–5")
    if high_epss_findings:
        priority_reasons.append(f"{high_epss_findings} finding(s) com EPSS >= 50%")

    if (
        (kev_findings and (ransomware_findings or sla_breached or external_assets or critical_assets))
        or (ransomware_findings and external_assets)
    ):
        priority = "P0"
        priority_label = "remediar agora"
    elif (
        kev_findings
        or ransomware_findings
        or sla_breached
        or (max_epss >= 0.5 and (external_assets or critical_assets))
    ):
        priority = "P1"
        priority_label = "prioridade imediata"
    elif sla_due_soon or max_epss >= 0.2 or critical_assets:
        priority = "P2"
        priority_label = "programar próximo ciclo"
    else:
        priority = "P3"
        priority_label = "planejado"

    if not priority_reasons:
        priority_reasons.append("sem sinal de ameaça/SLA que justifique escalonamento adicional")

    change_reasons = []
    if confidence in {"low", "insufficient_data"}:
        change_reasons.append(
            "histórico local de deploy insuficiente"
            if confidence == "insufficient_data"
            else "histórico local de falha exige cautela"
        )
    if critical_assets:
        change_reasons.append("inclui ativos críticos")
    if asset_count >= 50:
        change_reasons.append("blast radius elevado")
    if external_assets and critical_assets:
        change_reasons.append("população combina exposição externa e ativos críticos")

    if (confidence in {"low", "insufficient_data"} and critical_assets) or asset_count >= 100:
        change_level = "high"
    elif confidence in {"low", "insufficient_data"} or critical_assets or asset_count >= 50:
        change_level = "medium"
    else:
        change_level = "low"

    # Preserve the established confidence-driven rollout contract while adding
    # finer canaries only when local evidence is already strong.
    if confidence == "insufficient_data":
        mode = "pilot_collect_evidence"
        ring_plan = [10, 30, 100]
    elif confidence == "low":
        mode = "pilot_review_failures"
        ring_plan = [10, 30, 100]
    elif confidence == "medium":
        mode = "pilot_then_expand"
        ring_plan = [10, 30, 100]
    elif change_level == "high" and asset_count >= 20:
        mode = "guarded_canary"
        ring_plan = [5, 10, 30, 100]
    else:
        mode = "controlled_rollout"
        ring_plan = [30, 100] if asset_count >= 10 else [100]

    return {
        "priority": {
            "tier": priority,
            "label": priority_label,
            "reasons": priority_reasons,
        },
        "change_risk": {
            "level": change_level,
            "reasons": change_reasons or ["mudança com evidência local e blast radius controlado"],
            "patch_confidence": confidence,
        },
        "deployment_guidance": {
            "mode": mode,
            "suggested_ring_percent": ring_plan[0],
            "ring_plan": ring_plan,
            "health_gate_required": True,
            "rollback_checkpoint_recommended": True,
            "rollback_checkpoint_required": change_level == "high" and critical_assets > 0,
            "maintenance_window_recommended": critical_assets > 0 or asset_count >= 50,
            "approval_required": priority == "P0" or change_level == "high",
            "reason": (
                f"{priority} / change-risk {change_level}; "
                f"patch-confidence {confidence}; rollout progressivo com validação entre rings"
            ),
        },
    }


def remediation_hub_report(
    db: Session,
    reference: datetime | None = None,
    limit: int = 100,
) -> dict:
    reference = reference or now()
    agents = db.query(Agent).options(
        selectinload(Agent.vulnerabilities),
        selectinload(Agent.risk_profile),
    ).order_by(Agent.hostname.asc()).all()
    policies = db.query(AssetRiskPolicy).filter(
        AssetRiskPolicy.enabled.is_(True)
    ).order_by(
        AssetRiskPolicy.priority.desc(),
        AssetRiskPolicy.name.asc(),
    ).all()
    confidence = {
        item["patch_ref"].lower(): item
        for item in patch_confidence_report(db, limit=1000)["items"]
    }

    groups: dict[str, dict] = {}
    for agent in agents:
        open_findings = [
            finding for finding in (agent.vulnerabilities or [])
            if finding.status == "open"
        ]
        if not open_findings:
            continue

        for finding in open_findings:
            refs = sorted({
                str(ref).strip()
                for ref in load(finding.patch_refs_json, [])
                if str(ref).strip()
            })
            for patch_ref in refs:
                key = patch_ref.lower()
                group = groups.setdefault(key, {
                    "patch_ref": patch_ref,
                    "findings_by_agent": {},
                    "finding_ids": set(),
                    "cves": set(),
                    "severities": set(),
                    "max_cvss": 0.0,
                    "kev_findings": 0,
                    "ransomware_findings": 0,
                    "high_epss_findings": 0,
                    "max_epss": 0.0,
                    "sla_breached": 0,
                    "sla_due_soon": 0,
                })
                group["findings_by_agent"].setdefault(agent.id, set()).add(finding.id)
                if finding.id not in group["finding_ids"]:
                    group["finding_ids"].add(finding.id)
                    detection = finding_detection_risk(finding, reference)
                    sla = vulnerability_sla(finding, reference)
                    group["kev_findings"] += 1 if detection["kev"] else 0
                    group["ransomware_findings"] += 1 if detection["ransomware"] else 0
                    epss = detection["epss"]
                    if epss is not None:
                        group["max_epss"] = max(group["max_epss"], float(epss))
                        group["high_epss_findings"] += 1 if float(epss) >= 0.5 else 0
                    group["sla_breached"] += 1 if sla["state"] == "breached" else 0
                    group["sla_due_soon"] += 1 if sla["state"] == "due_soon" else 0
                if finding.cve:
                    group["cves"].add(finding.cve)
                group["severities"].add(str(finding.severity or "unknown").lower())
                group["max_cvss"] = max(group["max_cvss"], float(finding.cvss or 0.0))

    items = []
    agent_map = {agent.id: agent for agent in agents}
    for group in groups.values():
        before_total = 0.0
        after_total = 0.0
        appetite_crossings = 0
        affected_assets = []
        os_families = set()
        external_assets = 0
        critical_assets = 0

        for agent_id, finding_ids in group["findings_by_agent"].items():
            agent = agent_map[agent_id]
            open_findings = [
                finding for finding in (agent.vulnerabilities or [])
                if finding.status == "open"
            ]
            before = asset_risk_score(agent, open_findings, reference)
            after_findings = [
                finding for finding in open_findings
                if finding.id not in finding_ids
            ]
            after = asset_risk_score(agent, after_findings, reference)
            policy = effective_asset_risk_policy(db, agent, policies=policies)

            before_total += before["score"]
            after_total += after["score"]
            crossed = (
                before["score"] >= policy["risk_appetite"]
                and after["score"] < policy["risk_appetite"]
            )
            appetite_crossings += 1 if crossed else 0
            os_families.add(str(agent.os_family or "unknown").lower())
            criticality = asset_criticality(agent)["score"]
            external = asset_exposure(agent)["external"]
            external_assets += 1 if external else 0
            critical_assets += 1 if criticality >= 4 else 0
            affected_assets.append({
                "agent_id": agent.id,
                "hostname": agent.hostname,
                "os_family": agent.os_family,
                "finding_count": len(finding_ids),
                "before_score": before["score"],
                "projected_score": after["score"],
                "risk_reduction": round(max(0.0, before["score"] - after["score"]), 1),
                "risk_appetite": policy["risk_appetite"],
                "crosses_below_appetite": crossed,
                "criticality": criticality,
                "external": external,
            })

        reduction = round(max(0.0, before_total - after_total), 1)
        reduction_percent = (
            round(reduction / before_total * 100.0, 1)
            if before_total > 0
            else 0.0
        )
        affected_assets.sort(key=lambda item: (-item["risk_reduction"], item["hostname"].lower()))
        confidence_item = confidence.get(group["patch_ref"].lower())
        decision = remediation_group_decision(
            kev_findings=group["kev_findings"],
            ransomware_findings=group["ransomware_findings"],
            high_epss_findings=group["high_epss_findings"],
            max_epss=group["max_epss"],
            sla_breached=group["sla_breached"],
            sla_due_soon=group["sla_due_soon"],
            external_assets=external_assets,
            critical_assets=critical_assets,
            asset_count=len(group["findings_by_agent"]),
            patch_confidence=confidence_item,
        )
        deployment_guidance = decision["deployment_guidance"]

        items.append({
            "patch_ref": group["patch_ref"],
            "finding_count": len(group["finding_ids"]),
            "asset_count": len(group["findings_by_agent"]),
            "cves": sorted(group["cves"]),
            "cve_count": len(group["cves"]),
            "severities": sorted(group["severities"]),
            "max_cvss": round(group["max_cvss"], 1),
            "before_risk_total": round(before_total, 1),
            "projected_risk_total": round(after_total, 1),
            "risk_reduction": reduction,
            "reduction_percent": reduction_percent,
            "appetite_crossings": appetite_crossings,
            "os_families": sorted(os_families),
            "single_asset_campaign_ready": len(group["findings_by_agent"]) == 1,
            "primary_finding_id": next(iter(group["finding_ids"])) if len(group["finding_ids"]) == 1 else None,
            "patch_confidence": confidence_item,
            "priority": decision["priority"],
            "change_risk": decision["change_risk"],
            "deployment_guidance": deployment_guidance,
            "threat_sla": {
                "kev_findings": group["kev_findings"],
                "ransomware_findings": group["ransomware_findings"],
                "high_epss_findings": group["high_epss_findings"],
                "max_epss": round(group["max_epss"], 4),
                "sla_breached": group["sla_breached"],
                "sla_due_soon": group["sla_due_soon"],
                "external_assets": external_assets,
                "critical_assets": critical_assets,
            },
            "affected_assets": affected_assets,
        })

    items.sort(key=lambda item: (
        REMEDIATION_PRIORITY_ORDER.get(item["priority"]["tier"], 9),
        -item["risk_reduction"],
        -item["appetite_crossings"],
        -item["finding_count"],
        -item["max_cvss"],
        item["patch_ref"].lower(),
    ))
    items = items[:max(1, min(limit, 500))]
    return {
        "generated_at": reference.isoformat(),
        "mode": "simulation_only",
        "summary": {
            "remediation_groups": len(items),
            "findings_covered": len({
                finding_id
                for group in groups.values()
                for finding_id in group["finding_ids"]
            }),
            "assets_covered": len({
                agent_id
                for group in groups.values()
                for agent_id in group["findings_by_agent"]
            }),
            "appetite_crossings": sum(item["appetite_crossings"] for item in items),
            "priority_p0": sum(1 for item in items if item["priority"]["tier"] == "P0"),
            "priority_p1": sum(1 for item in items if item["priority"]["tier"] == "P1"),
            "high_change_risk": sum(1 for item in items if item["change_risk"]["level"] == "high"),
            "kev_findings": sum(item["threat_sla"]["kev_findings"] for item in items),
            "sla_breached": sum(item["threat_sla"]["sla_breached"] for item in items),
        },
        "items": items,
        "note": "Each row simulates remediation of all open findings linked to the same patch reference. Risk is recalculated per asset before aggregation.",
    }


def risk_reduction_plan_report(
    db: Session,
    agent_id: str,
    reference: datetime | None = None,
    max_steps: int = 25,
) -> dict:
    reference = reference or now()
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")

    remaining = [
        finding
        for finding in (agent.vulnerabilities or [])
        if finding.status == "open"
    ]
    policy = effective_asset_risk_policy(db, agent)
    current = asset_risk_score(agent, remaining, reference)
    initial_score = current["score"]
    steps = []
    max_steps = max(1, min(max_steps, 100))

    while (
        remaining
        and len(steps) < max_steps
        and current["score"] >= policy["risk_appetite"]
    ):
        candidates = []
        for finding in remaining:
            after_findings = [
                candidate for candidate in remaining
                if candidate.id != finding.id
            ]
            after = asset_risk_score(agent, after_findings, reference)
            marginal = round(max(0.0, current["score"] - after["score"]), 1)
            recommendation = remediation_recommendation(finding, reference)
            candidates.append({
                "finding": finding,
                "after_findings": after_findings,
                "after": after,
                "marginal": marginal,
                "recommendation": recommendation,
            })

        candidates.sort(key=lambda item: (
            -item["marginal"],
            -item["recommendation"]["priority_score"],
            -float(item["finding"].cvss or 0),
            item["finding"].id,
        ))
        selected = candidates[0]
        finding = selected["finding"]
        after = selected["after"]
        cumulative = round(max(0.0, initial_score - after["score"]), 1)

        steps.append({
            "step": len(steps) + 1,
            "finding_id": finding.id,
            "cve": finding.cve,
            "title": finding.title,
            "severity": finding.severity,
            "cvss": finding.cvss,
            "action": selected["recommendation"]["action"],
            "priority_score": selected["recommendation"]["priority_score"],
            "eligible_for_campaign": selected["recommendation"]["eligible_for_campaign"],
            "patch_refs": selected["recommendation"]["patch_refs"],
            "before_score": current["score"],
            "after_score": after["score"],
            "marginal_reduction": selected["marginal"],
            "cumulative_reduction": cumulative,
            "crosses_below_appetite": (
                current["score"] >= policy["risk_appetite"]
                and after["score"] < policy["risk_appetite"]
            ),
        })

        remaining = selected["after_findings"]
        current = after

    return {
        "generated_at": reference.isoformat(),
        "mode": "simulation_only",
        "asset": {
            "agent_id": agent.id,
            "hostname": agent.hostname,
        },
        "risk_appetite": policy["risk_appetite"],
        "initial_score": initial_score,
        "projected_score": current["score"],
        "projected_level": current["level"],
        "target_reached": current["score"] < policy["risk_appetite"],
        "steps": steps,
        "remaining_open_findings": len(remaining),
        "note": "Greedy marginal plan. Each step is recalculated from the remaining finding set and does not modify real state.",
    }


def vulnerability_sla_report(db: Session, reference: datetime | None = None) -> dict:
    reference = reference or now()
    findings = db.query(VulnerabilityFinding).all()
    summary = {
        "active": 0,
        "within_sla": 0,
        "due_soon": 0,
        "breached": 0,
        "excluded": 0,
        "exception": 0,
    }
    by_severity = {}
    items = []

    for finding in findings:
        sla = vulnerability_sla(finding, reference)
        state = sla["state"]
        summary[state] = summary.get(state, 0) + 1
        if sla["active"]:
            summary["active"] += 1

        severity = str(finding.severity or "unknown").strip().lower()
        bucket = by_severity.setdefault(
            severity,
            {"active": 0, "within_sla": 0, "due_soon": 0, "breached": 0, "exception": 0},
        )
        if sla["active"]:
            bucket["active"] += 1
        if sla["open"]:
            bucket[state] = bucket.get(state, 0) + 1

        items.append({
            "id": finding.id,
            "cve": finding.cve,
            "title": finding.title,
            "severity": severity,
            "status": finding.status,
            "agent_id": finding.agent_id,
            "hostname": finding.agent.hostname if finding.agent else "",
            "first_seen": finding.first_seen.isoformat() if finding.first_seen else None,
            "last_seen": finding.last_seen.isoformat() if finding.last_seen else None,
            "sla": sla,
        })

    state_rank = {"breached": 0, "due_soon": 1, "within_sla": 2, "exception": 3, "excluded": 4}
    items.sort(key=lambda item: (
        state_rank.get(item["sla"]["state"], 9),
        item["sla"]["remaining_hours"],
        item["severity"],
        item["cve"],
    ))

    return {
        "generated_at": reference.isoformat(),
        "policy": {
            "hours_by_severity": VULNERABILITY_SLA_HOURS,
            "due_soon_hours": VULNERABILITY_SLA_DUE_SOON_HOURS,
            "active_statuses": ["open"],
        },
        "summary": summary,
        "by_severity": by_severity,
        "items": items,
    }


ASSET_CRITICALITY_TAGS = {
    "tier0": 5,
    "mission-critical": 5,
    "critical": 5,
    "prod": 4,
    "production": 4,
    "database": 4,
    "domain-controller": 5,
    "identity": 5,
    "staging": 2,
    "dev": 1,
    "development": 1,
    "lab": 1,
}

ASSET_RISK_SEVERITY_WEIGHTS = {
    "critical": 2.0,
    "high": 1.5,
    "medium": 1.0,
    "low": 0.5,
    "unknown": 0.5,
}


def serialize_asset_risk_treatment(
    treatment: AssetRiskTreatment,
    reference: datetime | None = None,
) -> dict:
    reference = reference or now()
    due_at = treatment.due_at
    if due_at.tzinfo is None:
        due_at = due_at.replace(tzinfo=timezone.utc)
    completed_at = treatment.completed_at
    if completed_at and completed_at.tzinfo is None:
        completed_at = completed_at.replace(tzinfo=timezone.utc)
    active = treatment.status in {"planned", "in_progress"}
    overdue = active and due_at < reference
    return {
        "id": treatment.id,
        "agent_id": treatment.agent_id,
        "owner": treatment.owner,
        "action": treatment.action,
        "due_at": due_at.isoformat(),
        "status": treatment.status,
        "active": active,
        "overdue": overdue,
        "created_by": treatment.created_by,
        "updated_by": treatment.updated_by,
        "completion_evidence": treatment.completion_evidence,
        "completed_at": completed_at.isoformat() if completed_at else None,
        "created_at": treatment.created_at.isoformat() if treatment.created_at else None,
        "updated_at": treatment.updated_at.isoformat() if treatment.updated_at else None,
    }


def active_asset_risk_treatment(
    agent: Agent,
    reference: datetime | None = None,
) -> AssetRiskTreatment | None:
    active = [
        treatment for treatment in (agent.risk_treatments or [])
        if treatment.status in {"planned", "in_progress"}
    ]
    if not active:
        return None
    active.sort(
        key=lambda treatment: treatment.updated_at or treatment.created_at or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return active[0]


def serialize_asset_risk_acceptance(
    acceptance: AssetRiskAcceptance,
    reference: datetime | None = None,
) -> dict:
    reference = reference or now()
    expires_at = acceptance.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    revoked_at = acceptance.revoked_at
    if revoked_at and revoked_at.tzinfo is None:
        revoked_at = revoked_at.replace(tzinfo=timezone.utc)
    active = acceptance.revoked_at is None and expires_at > reference
    return {
        "id": acceptance.id,
        "agent_id": acceptance.agent_id,
        "reason": acceptance.reason,
        "approved_by": acceptance.approved_by,
        "expires_at": expires_at.isoformat(),
        "revoked_at": revoked_at.isoformat() if revoked_at else None,
        "revoked_by": acceptance.revoked_by,
        "revoke_reason": acceptance.revoke_reason,
        "created_at": acceptance.created_at.isoformat() if acceptance.created_at else None,
        "active": active,
        "expired": acceptance.revoked_at is None and expires_at <= reference,
    }


def active_asset_risk_acceptance(
    agent: Agent,
    reference: datetime | None = None,
) -> AssetRiskAcceptance | None:
    reference = reference or now()
    active = []
    for acceptance in agent.risk_acceptances or []:
        expires_at = acceptance.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if acceptance.revoked_at is None and expires_at > reference:
            active.append(acceptance)
    if not active:
        return None
    active.sort(key=lambda item: item.expires_at)
    return active[0]


def serialize_asset_risk_policy(policy: AssetRiskPolicy) -> dict:
    return {
        "id": policy.id,
        "name": policy.name,
        "target_tag": policy.target_tag,
        "risk_appetite": policy.risk_appetite,
        "priority": policy.priority,
        "enabled": policy.enabled,
        "reason": policy.reason,
        "created_by": policy.created_by,
        "updated_by": policy.updated_by,
        "created_at": policy.created_at.isoformat() if policy.created_at else None,
        "updated_at": policy.updated_at.isoformat() if policy.updated_at else None,
    }


def effective_asset_risk_policy(
    db: Session,
    agent: Agent,
    policies: list[AssetRiskPolicy] | None = None,
) -> dict:
    tags = {
        str(tag).strip().lower()
        for tag in load(agent.tags, [])
        if str(tag).strip()
    }
    if policies is None:
        policies = db.query(AssetRiskPolicy).filter(
            AssetRiskPolicy.enabled.is_(True)
        ).order_by(
            AssetRiskPolicy.priority.desc(),
            AssetRiskPolicy.name.asc(),
        ).all()

    for policy in policies:
        if str(policy.target_tag or "").strip().lower() in tags:
            return {
                "source": "policy",
                "policy": serialize_asset_risk_policy(policy),
                "risk_appetite": policy.risk_appetite,
            }

    return {
        "source": "global",
        "policy": None,
        "risk_appetite": min(1000, ASSET_RISK_APPETITE),
    }


def require_asset_above_risk_appetite(
    db: Session,
    agent: Agent,
    reference: datetime | None = None,
) -> tuple[dict, dict]:
    reference = reference or now()
    risk = asset_risk_score(agent, list(agent.vulnerabilities or []), reference)
    policy = effective_asset_risk_policy(db, agent)
    if risk["score"] < policy["risk_appetite"]:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "asset is not above its effective risk appetite",
                "score": risk["score"],
                "risk_appetite": policy["risk_appetite"],
            },
        )
    return risk, policy


def agent_ids_matching_risk_tags(db: Session, tags: set[str]) -> set[str]:
    normalized = {str(tag).strip().lower() for tag in tags if str(tag).strip()}
    if not normalized:
        return set()
    matched = set()
    for agent in db.query(Agent).all():
        agent_tags = {
            str(tag).strip().lower()
            for tag in load(agent.tags, [])
            if str(tag).strip()
        }
        if agent_tags.intersection(normalized):
            matched.add(agent.id)
    return matched


def serialize_asset_risk_profile(profile: AssetRiskProfile | None) -> dict | None:
    if not profile:
        return None
    return {
        "agent_id": profile.agent_id,
        "criticality": profile.criticality_override,
        "external": profile.external_override,
        "compensating_controls": (
            load(profile.controls_json, [])
            if profile.controls_json is not None
            else None
        ),
        "owner": profile.owner,
        "business_service": profile.business_service,
        "environment": profile.environment,
        "reason": profile.reason,
        "updated_by": profile.updated_by,
        "updated_at": profile.updated_at.isoformat() if profile.updated_at else None,
    }


def asset_criticality(agent: Agent | None) -> dict:
    tags = []
    if agent:
        tags = [str(tag).strip().lower() for tag in load(agent.tags, []) if str(tag).strip()]

    if agent and agent.risk_profile and agent.risk_profile.criticality_override is not None:
        score = max(1, min(5, int(agent.risk_profile.criticality_override)))
        return {
            "score": score,
            "source": "profile",
            "contributors": [{"profile": True, "score": score}],
            "tags": tags,
        }

    contributors = [
        {"tag": tag, "score": ASSET_CRITICALITY_TAGS[tag]}
        for tag in tags
        if tag in ASSET_CRITICALITY_TAGS
    ]
    score = max([item["score"] for item in contributors], default=2)
    return {
        "score": score,
        "source": "tags" if contributors else "default",
        "contributors": sorted(contributors, key=lambda item: -item["score"]),
        "tags": tags,
    }


def parse_boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value == 1
    if value is None:
        return False
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "y", "known", "on"}:
        return True
    if normalized in {"", "0", "false", "no", "n", "unknown", "none", "null", "off"}:
        return False
    return False


def normalize_epss(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, str):
        normalized = value.strip()
        if not normalized:
            return None
        if normalized.endswith("%"):
            try:
                percent = float(normalized[:-1].strip())
            except ValueError:
                return None
            result = percent / 100.0
            return result if 0.0 <= result <= 1.0 else None
        value = normalized
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if 0.0 <= result <= 1.0 else None


def finding_detection_risk(finding: VulnerabilityFinding, reference: datetime | None = None) -> dict:
    reference = reference or now()
    raw = load(finding.raw_json, {})
    threat = raw.get("threat_intel") if isinstance(raw.get("threat_intel"), dict) else raw
    factors = []

    cvss = max(0.0, min(10.0, float(finding.cvss or 0.0)))
    cvss_points = cvss * 6.0
    score = cvss_points
    factors.append({"factor": "cvss", "points": round(cvss_points, 1), "value": cvss})

    epss = normalize_epss(threat.get("epss"))
    if epss is not None:
        points = epss * 20.0
        score += points
        factors.append({"factor": "epss", "points": round(points, 1), "value": epss})

    kev = any(parse_boolish(value) for value in (threat.get("kev"), raw.get("known_exploited"), raw.get("cisa_kev")))
    if kev:
        score += 15
        factors.append({"factor": "known_exploited", "points": 15, "value": True})

    ransomware = str(threat.get("kev_ransomware_use") or "").strip().lower()
    ransomware_known = ransomware in {"known", "yes", "true"} or parse_boolish(raw.get("ransomware"))
    if ransomware_known:
        score += 10
        factors.append({"factor": "ransomware", "points": 10, "value": True})

    first_seen = finding.first_seen or finding.created_at or reference
    if first_seen.tzinfo is None:
        first_seen = first_seen.replace(tzinfo=timezone.utc)
    age_days = max(0.0, (reference - first_seen).total_seconds() / 86400.0)
    age_points = min(10.0, age_days / 9.0)
    if age_points:
        score += age_points
        factors.append({"factor": "age", "points": round(age_points, 1), "value_days": round(age_days, 1)})

    score = round(max(1.0, min(100.0, score)), 1)
    if score >= 90:
        level = "critical"
    elif score >= 70:
        level = "high"
    elif score >= 40:
        level = "medium"
    else:
        level = "low"

    return {
        "score": score,
        "level": level,
        "cvss": cvss,
        "epss": epss,
        "kev": kev,
        "ransomware": ransomware_known,
        "age_days": round(age_days, 1),
        "factors": factors,
    }


def asset_exposure(agent: Agent | None) -> dict:
    criticality = asset_criticality(agent)
    tags = set(criticality["tags"])

    if agent and agent.risk_profile and agent.risk_profile.external_override is not None:
        external = bool(agent.risk_profile.external_override)
        return {
            "external": external,
            "multiplier": 1.2 if external else 1.0,
            "contributors": ["risk_profile"],
            "source": "profile",
        }

    external_tags = sorted(tags.intersection({"internet-facing", "public", "dmz", "external"}))
    external = bool(external_tags)
    return {
        "external": external,
        "multiplier": 1.2 if external else 1.0,
        "contributors": external_tags,
        "source": "tags" if external_tags else "default",
    }


def asset_compensating_factor(agent: Agent | None) -> dict:
    tags = set(asset_criticality(agent)["tags"])
    source = "tags"

    if agent and agent.risk_profile and agent.risk_profile.controls_json is not None:
        tags = {
            str(value).strip().lower()
            for value in load(agent.risk_profile.controls_json, [])
            if str(value).strip()
        }
        source = "profile"

    controls = []
    multiplier = 1.0
    if "segmented" in tags:
        multiplier *= 0.9
        controls.append({"tag": "segmented", "multiplier": 0.9})
    if "edr-protected" in tags:
        multiplier *= 0.9
        controls.append({"tag": "edr-protected", "multiplier": 0.9})
    if "restricted-egress" in tags:
        multiplier *= 0.95
        controls.append({"tag": "restricted-egress", "multiplier": 0.95})
    multiplier = max(0.6, round(multiplier, 4))
    return {
        "multiplier": multiplier,
        "controls": controls,
        "source": source,
    }


def asset_risk_score(agent: Agent, findings: list[VulnerabilityFinding], reference: datetime | None = None) -> dict:
    reference = reference or now()
    open_findings = [finding for finding in findings if finding.status == "open"]
    criticality = asset_criticality(agent)
    exposure = asset_exposure(agent)
    compensating = asset_compensating_factor(agent)

    buckets = {}
    top_factors = []
    for finding in open_findings:
        detection = finding_detection_risk(finding, reference)
        severity = str(finding.severity or "unknown").lower()
        bucket = buckets.setdefault(severity, [])
        bucket.append(detection["score"])
        if detection["kev"]:
            top_factors.append("CISA KEV")
        if detection["ransomware"]:
            top_factors.append("ransomware")
        if detection["epss"] is not None and detection["epss"] >= 0.5:
            top_factors.append("EPSS alto")

    weighted = 0.0
    bucket_breakdown = {}
    for severity, scores in buckets.items():
        avg_score = sum(scores) / len(scores)
        count_factor = math.pow(max(1, len(scores)), 0.01)
        weight = ASSET_RISK_SEVERITY_WEIGHTS.get(severity, 0.5)
        contribution = avg_score * count_factor * weight
        weighted += contribution
        bucket_breakdown[severity] = {
            "count": len(scores),
            "average_detection_risk": round(avg_score, 1),
            "weight": weight,
            "contribution": round(contribution, 1),
        }

    base_weighted = weighted
    criticality_effect = base_weighted * max(0.0, criticality["score"] - 1)
    exposure_effect = base_weighted * criticality["score"] * max(0.0, exposure["multiplier"] - 1.0)
    pre_compensation = base_weighted * criticality["score"] * exposure["multiplier"]
    compensation_reduction = pre_compensation * max(0.0, 1.0 - compensating["multiplier"])

    raw_score = pre_compensation * compensating["multiplier"]
    score = round(min(1000.0, raw_score), 1)

    contributor_values = []
    for severity, data in bucket_breakdown.items():
        contributor_values.append({
            "name": f"findings:{severity}",
            "category": "vulnerabilities",
            "raw": round(data["contribution"], 1),
        })
    if criticality_effect > 0:
        contributor_values.append({
            "name": "asset_criticality",
            "category": "asset_context",
            "raw": round(criticality_effect, 1),
        })
    if exposure_effect > 0:
        contributor_values.append({
            "name": "external_exposure",
            "category": "asset_context",
            "raw": round(exposure_effect, 1),
        })
    if compensation_reduction > 0:
        contributor_values.append({
            "name": "compensating_controls",
            "category": "risk_reduction",
            "raw": round(-compensation_reduction, 1),
        })

    positive_total = sum(max(0.0, item["raw"]) for item in contributor_values)
    decomposition = []
    for item in contributor_values:
        contribution_percent = (
            round(max(0.0, item["raw"]) / positive_total * 100, 1)
            if positive_total and item["raw"] > 0
            else 0.0
        )
        decomposition.append({
            **item,
            "percent": contribution_percent,
        })
    decomposition.sort(key=lambda item: abs(item["raw"]), reverse=True)

    if score >= 850:
        level = "critical"
    elif score >= 700:
        level = "high"
    elif score >= 500:
        level = "medium"
    else:
        level = "low"

    if exposure["external"]:
        top_factors.append("exposição externa")
    if criticality["score"] >= 4:
        top_factors.append("ativo crítico")

    return {
        "score": score,
        "level": level,
        "asset_criticality": criticality,
        "exposure": exposure,
        "compensating": compensating,
        "open_findings": len(open_findings),
        "buckets": bucket_breakdown,
        "decomposition": decomposition,
        "calculation": {
            "base_weighted": round(base_weighted, 4),
            "criticality_multiplier": criticality["score"],
            "exposure_multiplier": exposure["multiplier"],
            "compensating_multiplier": compensating["multiplier"],
            "pre_compensation": round(pre_compensation, 4),
            "raw_score": round(raw_score, 4),
            "score_cap": 1000,
            "capped": raw_score > 1000.0,
        },
        "top_factors": sorted(set(top_factors)),
    }


def capture_asset_risk_snapshots(
    db: Session,
    source: str = "manual",
    reference: datetime | None = None,
    minimum_interval_seconds: int = 3600,
    agent_ids: set[str] | None = None,
) -> dict:
    reference = reference or now()
    report = asset_risk_report(db, reference, agent_ids=agent_ids)
    created = 0
    skipped = 0

    for item in report["assets"]:
        latest = db.query(AssetRiskSnapshot).filter(
            AssetRiskSnapshot.agent_id == item["agent_id"]
        ).order_by(AssetRiskSnapshot.captured_at.desc()).first()

        if latest:
            captured = latest.captured_at
            if captured.tzinfo is None:
                captured = captured.replace(tzinfo=timezone.utc)
            if (reference - captured).total_seconds() < minimum_interval_seconds:
                skipped += 1
                continue

        risk = item["risk"]
        db.add(AssetRiskSnapshot(
            agent_id=item["agent_id"],
            score=risk["score"],
            level=risk["level"],
            criticality=risk["asset_criticality"]["score"],
            external=risk["exposure"]["external"],
            open_findings=risk["open_findings"],
            factors_json=dump(risk["top_factors"]),
            model_version=report["model"],
            decomposition_json=dump(risk.get("decomposition", [])),
            calculation_json=dump(risk.get("calculation", {})),
            risk_policy_json=dump(item.get("risk_policy", {})),
            risk_appetite=int(risk.get("risk_appetite") or ASSET_RISK_APPETITE),
            governance_status=str(risk.get("governance_status") or ""),
            source=source,
            captured_at=reference,
        ))
        created += 1

    cutoff = reference - timedelta(days=ASSET_RISK_HISTORY_RETENTION_DAYS)
    prune_query = db.query(AssetRiskSnapshot).filter(
        AssetRiskSnapshot.captured_at < cutoff
    )
    pruned = prune_query.delete(synchronize_session=False)
    db.commit()
    return {
        "created": created,
        "skipped": skipped,
        "pruned": pruned,
        "retention_days": ASSET_RISK_HISTORY_RETENTION_DAYS,
        "source": source,
        "captured_at": reference.isoformat(),
    }


def asset_risk_history(db: Session, agent_id: str | None = None, limit: int = 500) -> dict:
    q = db.query(AssetRiskSnapshot)
    if agent_id:
        q = q.filter(AssetRiskSnapshot.agent_id == agent_id)
    rows = q.order_by(AssetRiskSnapshot.captured_at.desc()).limit(max(1, min(limit, 5000))).all()

    items = []
    for row in rows:
        items.append({
            "id": row.id,
            "agent_id": row.agent_id,
            "hostname": row.agent.hostname if row.agent else "",
            "score": row.score,
            "level": row.level,
            "criticality": row.criticality,
            "external": row.external,
            "open_findings": row.open_findings,
            "top_factors": load(row.factors_json, []),
            "model_version": row.model_version,
            "decomposition": load(row.decomposition_json, []),
            "calculation": load(row.calculation_json, {}),
            "risk_policy": load(row.risk_policy_json, {}),
            "risk_appetite": row.risk_appetite,
            "governance_status": row.governance_status,
            "source": row.source,
            "captured_at": row.captured_at.isoformat() if row.captured_at else None,
        })

    return {
        "agent_id": agent_id,
        "items": items,
    }


def asset_risk_report(
    db: Session,
    reference: datetime | None = None,
    agent_ids: set[str] | None = None,
) -> dict:
    reference = reference or now()
    agent_query = db.query(Agent).options(
        selectinload(Agent.vulnerabilities),
        selectinload(Agent.risk_profile),
        selectinload(Agent.risk_acceptances),
        selectinload(Agent.risk_treatments),
    )
    if agent_ids:
        agent_query = agent_query.filter(Agent.id.in_(agent_ids))
    agents = agent_query.order_by(Agent.hostname.asc()).all()
    policies = db.query(AssetRiskPolicy).filter(
        AssetRiskPolicy.enabled.is_(True)
    ).order_by(
        AssetRiskPolicy.priority.desc(),
        AssetRiskPolicy.name.asc(),
    ).all()

    rows = []
    for agent in agents:
        findings = list(agent.vulnerabilities or [])
        risk = asset_risk_score(agent, findings, reference)
        policy = effective_asset_risk_policy(db, agent, policies=policies)
        acceptance = active_asset_risk_acceptance(agent, reference)
        treatment = active_asset_risk_treatment(agent, reference)
        risk["risk_appetite"] = policy["risk_appetite"]
        risk["above_risk_appetite"] = risk["score"] >= policy["risk_appetite"]
        risk["governance_status"] = (
            "accepted"
            if risk["above_risk_appetite"] and acceptance
            else "treatment_overdue"
            if risk["above_risk_appetite"] and treatment and serialize_asset_risk_treatment(treatment, reference)["overdue"]
            else "in_treatment"
            if risk["above_risk_appetite"] and treatment
            else "above_appetite"
            if risk["above_risk_appetite"]
            else "within_appetite"
        )
        rows.append({
            "agent_id": agent.id,
            "hostname": agent.hostname,
            "ip_address": agent.ip_address,
            "os_family": agent.os_family,
            "tags": load(agent.tags, []),
            "risk_profile": serialize_asset_risk_profile(agent.risk_profile),
            "risk_policy": policy,
            "risk_acceptance": serialize_asset_risk_acceptance(acceptance, reference) if acceptance else None,
            "risk_treatment": serialize_asset_risk_treatment(treatment, reference) if treatment else None,
            "risk": risk,
        })

    rows.sort(key=lambda row: (-row["risk"]["score"], row["hostname"].lower()))

    snapshots_by_agent: dict[str, list[AssetRiskSnapshot]] = {}
    agent_ids = [row["agent_id"] for row in rows]
    if agent_ids:
        ranked_snapshots = db.query(
            AssetRiskSnapshot.id.label("snapshot_id"),
            AssetRiskSnapshot.agent_id.label("agent_id"),
            func.row_number().over(
                partition_by=AssetRiskSnapshot.agent_id,
                order_by=AssetRiskSnapshot.captured_at.desc(),
            ).label("rn"),
        ).filter(
            AssetRiskSnapshot.agent_id.in_(agent_ids)
        ).subquery()

        latest_snapshots = db.query(AssetRiskSnapshot).join(
            ranked_snapshots,
            AssetRiskSnapshot.id == ranked_snapshots.c.snapshot_id,
        ).filter(
            ranked_snapshots.c.rn <= 2
        ).order_by(
            AssetRiskSnapshot.agent_id.asc(),
            AssetRiskSnapshot.captured_at.desc(),
        ).all()
        for snapshot in latest_snapshots:
            snapshots_by_agent.setdefault(snapshot.agent_id, []).append(snapshot)

    for row in rows:
        snapshots = snapshots_by_agent.get(row["agent_id"], [])
        current = row["risk"]["score"]
        if not snapshots:
            trend = {"delta": 0.0, "direction": "new", "previous_score": None}
        else:
            comparison = snapshots[0]
            if len(snapshots) > 1 and float(snapshots[0].score) == float(current):
                comparison = snapshots[1]
            previous = float(comparison.score)
            delta = round(current - previous, 1)
            if delta > 0:
                direction = "up"
            elif delta < 0:
                direction = "down"
            else:
                direction = "flat"
            trend = {
                "delta": delta,
                "direction": direction,
                "previous_score": previous,
                "last_snapshot_at": snapshots[0].captured_at.isoformat() if snapshots[0].captured_at else None,
                "comparison_snapshot_at": comparison.captured_at.isoformat() if comparison.captured_at else None,
            }
        row["risk"]["trend"] = trend

    contributor_totals = {}
    contributor_assets = {}
    for row in rows:
        for item in row["risk"].get("decomposition", []):
            if item["raw"] <= 0:
                continue
            name = item["name"]
            contributor_totals[name] = contributor_totals.get(name, 0.0) + item["raw"]
            contributor_assets.setdefault(name, set()).add(row["agent_id"])

    contributor_positive_total = sum(contributor_totals.values())
    top_contributors = [
        {
            "name": name,
            "raw": round(value, 1),
            "assets_affected": len(contributor_assets.get(name, set())),
            "share_percent": (
                round(value / contributor_positive_total * 100.0, 1)
                if contributor_positive_total > 0
                else 0.0
            ),
        }
        for name, value in sorted(
            contributor_totals.items(),
            key=lambda pair: pair[1],
            reverse=True,
        )[:10]
    ]

    summary = {
        "assets": len(rows),
        "critical": sum(1 for row in rows if row["risk"]["level"] == "critical"),
        "high": sum(1 for row in rows if row["risk"]["level"] == "high"),
        "medium": sum(1 for row in rows if row["risk"]["level"] == "medium"),
        "low": sum(1 for row in rows if row["risk"]["level"] == "low"),
        "external": sum(1 for row in rows if row["risk"]["exposure"]["external"]),
        "risk_appetite": min(1000, ASSET_RISK_APPETITE),
        "risk_policies": len(policies),
        "above_risk_appetite": sum(
            1 for row in rows
            if row["risk"]["above_risk_appetite"]
        ),
        "accepted_above_appetite": sum(
            1 for row in rows
            if row["risk"]["governance_status"] == "accepted"
        ),
        "unaccepted_above_appetite": sum(
            1 for row in rows
            if row["risk"]["governance_status"] == "above_appetite"
        ),
        "untreated_above_appetite": sum(
            1 for row in rows
            if row["risk"]["governance_status"] == "above_appetite"
        ),
        "in_treatment_above_appetite": sum(
            1 for row in rows
            if row["risk"]["governance_status"] == "in_treatment"
        ),
        "overdue_treatment_above_appetite": sum(
            1 for row in rows
            if row["risk"]["governance_status"] == "treatment_overdue"
        ),
        "average_score": round(
            sum(row["risk"]["score"] for row in rows) / len(rows), 1
        ) if rows else 0.0,
        "assets_with_owner": sum(
            1 for row in rows
            if (row.get("risk_profile") or {}).get("owner")
        ),
        "assets_without_owner": sum(
            1 for row in rows
            if not (row.get("risk_profile") or {}).get("owner")
        ),
        "assets_with_business_service": sum(
            1 for row in rows
            if (row.get("risk_profile") or {}).get("business_service")
        ),
        "critical_high_without_owner": sum(
            1 for row in rows
            if row["risk"]["level"] in {"critical", "high"}
            and not (row.get("risk_profile") or {}).get("owner")
        ),
    }
    return {
        "generated_at": reference.isoformat(),
        "model": "be_safe_asset_risk_v1",
        "scale": {"min": 0, "max": 1000},
        "summary": summary,
        "top_contributors": top_contributors,
        "assets": rows,
    }


RISK_ASSET_TAG_WEIGHTS = {
    "critical": 15,
    "mission-critical": 15,
    "tier0": 15,
    "prod": 10,
    "production": 10,
    "internet-facing": 15,
    "public": 10,
    "dmz": 10,
}


def vulnerability_risk(finding: VulnerabilityFinding, reference: datetime | None = None) -> dict:
    reference = reference or now()
    raw = load(finding.raw_json, {})
    threat = raw.get("threat_intel") if isinstance(raw.get("threat_intel"), dict) else raw
    reasons = []

    cvss = max(0.0, min(10.0, float(finding.cvss or 0.0)))
    cvss_points = round(cvss * 4.0, 1)
    score = cvss_points
    reasons.append({"factor": "cvss", "points": cvss_points, "value": cvss})

    epss = normalize_epss(threat.get("epss"))
    if epss is not None:
        epss_points = round(epss * 20.0, 1)
        score += epss_points
        reasons.append({"factor": "epss", "points": epss_points, "value": epss})

    kev = bool(threat.get("kev") or raw.get("known_exploited") or raw.get("cisa_kev"))
    if kev:
        score += 20
        reasons.append({"factor": "known_exploited", "points": 20, "value": True})

    first_seen = finding.first_seen or finding.created_at or reference
    if first_seen.tzinfo is None:
        first_seen = first_seen.replace(tzinfo=timezone.utc)
    age_days = max(0.0, (reference - first_seen).total_seconds() / 86400.0)
    age_points = min(10.0, age_days / 9.0)
    if age_points > 0:
        score += age_points
        reasons.append({"factor": "age", "points": round(age_points, 1), "value_days": round(age_days, 1)})

    asset_points = 0
    tags = []
    if finding.agent:
        tags = [str(tag).strip().lower() for tag in load(finding.agent.tags, []) if str(tag).strip()]
        for tag in tags:
            asset_points = max(asset_points, RISK_ASSET_TAG_WEIGHTS.get(tag, 0))
    if asset_points:
        score += asset_points
        reasons.append({"factor": "asset_criticality", "points": asset_points, "tags": tags})

    if finding.agent is None:
        score += 5
        reasons.append({"factor": "unmanaged_or_unmatched", "points": 5, "value": True})

    score = round(min(100.0, score), 1)
    if score >= 80:
        level = "urgent"
    elif score >= 60:
        level = "high"
    elif score >= 40:
        level = "medium"
    else:
        level = "low"

    return {
        "score": score,
        "level": level,
        "epss": epss,
        "kev": kev,
        "age_days": round(age_days, 1),
        "asset_tags": tags,
        "reasons": reasons,
    }


def match_agent_for_vulnerability(db: Session, host: str, ip_address: str):
    host_key = str(host or "").strip().lower().rstrip(".")
    short_host = host_key.split(".", 1)[0] if host_key else ""
    ip_key = str(ip_address or "").strip()

    for agent in db.query(Agent).all():
        if ip_key and agent.ip_address and agent.ip_address.strip() == ip_key:
            return agent
        agent_host = str(agent.hostname or "").strip().lower().rstrip(".")
        if host_key and agent_host:
            if agent_host == host_key:
                return agent
            if agent_host.split(".", 1)[0] == short_host:
                return agent
    return None


def serialize_remediation_evidence(item: RemediationEvidence):
    evidence = load(item.evidence_json, {})
    return {
        "id": item.id,
        "finding_id": item.finding_id,
        "campaign_id": item.campaign_id,
        "campaign_name": item.campaign.name if item.campaign else "",
        "job_id": item.job_id,
        "agent_id": item.agent_id,
        "hostname": item.agent.hostname if item.agent else "",
        "source": item.source,
        "cve": item.cve,
        "greenbone_task_id": item.greenbone_task_id,
        "baseline_report_id": item.baseline_report_id,
        "rescan_report_id": item.rescan_report_id,
        "status": item.status,
        "error": item.error,
        "evidence": evidence,
        "requested_at": item.requested_at.isoformat() if item.requested_at else None,
        "verified_at": item.verified_at.isoformat() if item.verified_at else None,
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "updated_at": item.updated_at.isoformat() if item.updated_at else None,
    }


def latest_remediation_evidence(finding: VulnerabilityFinding):
    items = list(finding.remediation_evidence or [])
    if not items:
        return None
    items.sort(key=lambda item: item.created_at or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return items[0]


def serialize_vulnerability(v: VulnerabilityFinding):
    return {
        "id": v.id,
        "source": v.source,
        "external_id": v.external_id,
        "scan_id": v.scan_id,
        "agent_id": v.agent_id,
        "hostname": v.agent.hostname if v.agent else "",
        "agent_os": v.agent.os_family if v.agent else "",
        "host": v.host,
        "ip_address": v.ip_address,
        "cve": v.cve,
        "title": v.title,
        "severity": v.severity,
        "cvss": v.cvss,
        "port": v.port,
        "solution": v.solution,
        "patch_refs": load(v.patch_refs_json, []),
        "status": v.status,
        "matched": bool(v.agent_id),
        "sla": vulnerability_sla(v),
        "risk": vulnerability_risk(v),
        "first_seen": v.first_seen.isoformat() if v.first_seen else None,
        "last_seen": v.last_seen.isoformat() if v.last_seen else None,
        "resolved_at": v.resolved_at.isoformat() if v.resolved_at else None,
        "remediation": (
            serialize_remediation_evidence(latest_remediation_evidence(v))
            if latest_remediation_evidence(v)
            else None
        ),
    }



GREENBONE_SYNC_LOCK = threading.Lock()
GREENBONE_STOP = threading.Event()
THREAT_INTEL_SYNC_LOCK = threading.Lock()
THREAT_INTEL_STOP = threading.Event()


def integration_state(db: Session, name: str) -> IntegrationState:
    state = db.get(IntegrationState, name)
    if not state:
        state = IntegrationState(name=name)
        db.add(state)
        db.commit()
    return state


def serialize_integration_state(state: IntegrationState, config: dict):
    return {
        "name": state.name,
        "enabled": config.get("enabled", False),
        "configured": config.get("configured", False),
        "status": state.status,
        "last_attempt_at": state.last_attempt_at.isoformat() if state.last_attempt_at else None,
        "last_success_at": state.last_success_at.isoformat() if state.last_success_at else None,
        "last_error": state.last_error,
        "details": load(state.details_json, {}),
        "config": config,
    }


def upsert_vulnerability_findings(db: Session, source: str, scan_id: str, findings):
    imported = 0
    created = 0
    updated = 0
    matched = 0
    seen_ids = set()
    timestamp = now()

    for finding in findings:
        value = finding if isinstance(finding, dict) else finding.model_dump()
        cves = sorted({normalize_cve(cve) for cve in value.get("cves", []) if normalize_cve(cve)})
        if not cves:
            cves = [""]

        agent = match_agent_for_vulnerability(db, value.get("host", ""), value.get("ip_address", ""))
        if agent:
            matched += len(cves)

        for cve in cves:
            external_id = str(value.get("external_id") or "")
            item = db.query(VulnerabilityFinding).filter(
                VulnerabilityFinding.source == source,
                VulnerabilityFinding.external_id == external_id,
                VulnerabilityFinding.cve == cve,
            ).first()

            if not item:
                item = VulnerabilityFinding(
                    id=str(uuid.uuid4()),
                    source=source,
                    external_id=external_id,
                    cve=cve,
                    first_seen=timestamp,
                )
                db.add(item)
                created += 1
            else:
                updated += 1

            raw = value.get("raw") or {}
            previous_raw = load(item.raw_json, {}) if item.raw_json else {}
            if (
                isinstance(previous_raw.get("threat_intel"), dict)
                and "threat_intel" not in raw
            ):
                raw["threat_intel"] = previous_raw["threat_intel"]
            item.scan_id = str(raw.get("greenbone_report_id") or scan_id or "")
            item.agent_id = agent.id if agent else None
            item.host = str(value.get("host") or "")
            item.ip_address = str(value.get("ip_address") or "")
            item.title = str(value.get("title") or "")
            item.severity = severity_from_cvss(value.get("cvss", 0), value.get("severity", ""))
            item.cvss = float(value.get("cvss") or 0)
            item.port = str(value.get("port") or "")
            item.solution = str(value.get("solution") or "")
            item.patch_refs_json = dump(sorted(set(value.get("patch_refs") or [])))
            item.raw_json = dump(raw)
            item.last_seen = timestamp

            if value.get("resolved"):
                item.status = "remediated"
                item.resolved_at = timestamp
            elif item.status not in {"accepted_risk", "false_positive"}:
                item.status = "open"
                item.resolved_at = None

            imported += 1
            seen_ids.add(external_id)

    db.commit()
    return {
        "normalized": imported,
        "created": created,
        "updated": updated,
        "matched": matched,
        "seen_ids": seen_ids,
    }


def reconcile_greenbone_absent(db: Session, reports, source: str = "openvas"):
    marked = 0
    for report in reports:
        task_id = str(report.get("task_id") or "")
        if not task_id:
            continue
        seen = set(report.get("external_ids") or [])
        prefix = f"{task_id}:%"
        candidates = db.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.source == source,
            VulnerabilityFinding.status == "open",
            VulnerabilityFinding.external_id.like(prefix),
        ).all()
        for item in candidates:
            if item.external_id not in seen:
                item.status = "not_detected"
                item.resolved_at = None
                marked += 1
    if marked:
        db.commit()
    return marked



def remediation_evidence_for_job(db: Session, job: PatchJob, payload: dict):
    finding_id = str(payload.get("source_finding_id") or "")
    if not finding_id or job.action != "install_updates":
        return None

    existing = db.query(RemediationEvidence).filter(RemediationEvidence.job_id == job.id).first()
    if existing:
        return existing

    finding = db.get(VulnerabilityFinding, finding_id)
    if not finding or finding.source != "openvas":
        return None

    raw = load(finding.raw_json, {})
    task_id = str(raw.get("greenbone_task_id") or "")
    status = "waiting_validation" if task_id else "unsupported"
    error = "" if task_id else "source finding has no Greenbone task id"

    item = RemediationEvidence(
        id=str(uuid.uuid4()),
        finding_id=finding.id,
        campaign_id=job.campaign_id,
        job_id=job.id,
        agent_id=job.agent_id,
        source=finding.source,
        cve=finding.cve,
        greenbone_task_id=task_id,
        baseline_report_id=finding.scan_id or str(raw.get("greenbone_report_id") or ""),
        status=status,
        error=error,
        evidence_json=dump({
            "source_external_id": finding.external_id,
            "source_last_seen": finding.last_seen.isoformat() if finding.last_seen else None,
            "source_status": finding.status,
            "source_title": finding.title,
            "source_cvss": finding.cvss,
            "source_port": finding.port,
        }),
    )
    db.add(item)
    return item


def remediation_scan_active_count(db: Session) -> int:
    return db.query(RemediationEvidence).filter(
        RemediationEvidence.status == "rescan_requested"
    ).count()


def start_remediation_rescan(db: Session, item: RemediationEvidence, actor: str) -> bool:
    if item.status == "verified":
        return False

    job = db.get(PatchJob, item.job_id)
    finding = db.get(VulnerabilityFinding, item.finding_id)
    if not job or not finding:
        item.status = "error"
        item.error = "job or source finding is unavailable"
        db.commit()
        return False

    validation = job_post_patch_validation(job)
    if validation.get("status") != "passed":
        return False

    if not item.greenbone_task_id:
        item.status = "unsupported"
        item.error = "source finding has no Greenbone task id"
        db.commit()
        return False

    config_obj = get_greenbone_config()
    config = public_greenbone_config(config_obj)
    if not config.get("enabled") or not config.get("configured"):
        item.status = "error"
        item.error = "Greenbone integration is not enabled and configured"
        db.commit()
        return False

    if not GREENBONE_SYNC_LOCK.acquire(blocking=False):
        return False

    try:
        started = start_greenbone_task_rescan(item.greenbone_task_id, config_obj)
        item.status = "rescan_requested"
        item.rescan_report_id = str(started.get("report_id") or "")
        item.requested_at = now()
        item.verified_at = None
        item.error = ""

        evidence = load(item.evidence_json, {})
        evidence.update({
            "validation": validation,
            "rescan": {
                "task_id": item.greenbone_task_id,
                "task_name": started.get("task_name", ""),
                "previous_status": started.get("previous_status", ""),
                "report_id": item.rescan_report_id,
                "requested_at": item.requested_at.isoformat(),
            },
        })
        item.evidence_json = dump(evidence)
        db.commit()
        audit(
            db,
            actor,
            "remediation.rescan.requested",
            "remediation_evidence",
            item.id,
            {
                "finding_id": item.finding_id,
                "campaign_id": item.campaign_id,
                "job_id": item.job_id,
                "task_id": item.greenbone_task_id,
                "report_id": item.rescan_report_id,
                "cve": item.cve,
            },
        )
        return True
    except Exception as exc:
        item.status = "error"
        item.error = str(exc)[:2000]
        evidence = load(item.evidence_json, {})
        evidence["rescan_error"] = {
            "time": now().isoformat(),
            "error": str(exc)[:1000],
        }
        item.evidence_json = dump(evidence)
        db.commit()
        audit(
            db,
            actor,
            "remediation.rescan.failed",
            "remediation_evidence",
            item.id,
            {"error": str(exc)[:1000]},
        )
        return False
    finally:
        GREENBONE_SYNC_LOCK.release()


def process_ready_remediation_rescans() -> int:
    db = SessionLocal()
    requested = 0
    try:
        items = db.query(RemediationEvidence).filter(
            RemediationEvidence.status == "waiting_validation"
        ).order_by(RemediationEvidence.created_at.asc()).limit(20).all()
        for item in items:
            if start_remediation_rescan(db, item, "system"):
                requested += 1
        return requested
    finally:
        db.close()


def reconcile_remediation_evidence(db: Session, reports) -> dict:
    report_map = {
        (str(report.get("task_id") or ""), str(report.get("report_id") or "")): report
        for report in reports
    }
    verified = 0
    still_detected = 0
    waiting = 0
    timestamp = now()

    items = db.query(RemediationEvidence).filter(
        RemediationEvidence.status == "rescan_requested"
    ).all()

    for item in items:
        report = report_map.get((item.greenbone_task_id, item.rescan_report_id))
        if not report:
            waiting += 1
            continue

        task_status = str(report.get("task_status") or "").strip().lower()
        if task_status != "done":
            waiting += 1
            continue

        finding = db.get(VulnerabilityFinding, item.finding_id)
        if not finding:
            item.status = "error"
            item.error = "source finding no longer exists"
            continue

        source_external_id = str(load(item.evidence_json, {}).get("source_external_id") or finding.external_id)
        source_key = source_external_id + "|" + str(item.cve or "")
        finding_keys = set(report.get("finding_keys") or [])
        detected = source_key in finding_keys if finding_keys else (
            source_external_id in set(report.get("external_ids") or [])
        )
        item.verified_at = timestamp
        item.error = ""

        evidence = load(item.evidence_json, {})
        evidence["verification"] = {
            "checked_at": timestamp.isoformat(),
            "task_id": item.greenbone_task_id,
            "task_status": report.get("task_status", ""),
            "report_id": item.rescan_report_id,
            "source_external_id": source_external_id,
            "source_key": source_key,
            "cve": item.cve,
            "detected": detected,
            "finding_count": report.get("finding_count", 0),
        }

        if detected:
            item.status = "still_detected"
            still_detected += 1
            if finding.status not in {"accepted_risk", "false_positive"}:
                finding.status = "open"
                finding.resolved_at = None
            event_type = "remediation.rescan.still_detected"
        else:
            item.status = "verified"
            verified += 1
            if finding.status not in {"accepted_risk", "false_positive"}:
                finding.status = "remediated"
                finding.resolved_at = timestamp
            event_type = "remediation.verified"

        item.evidence_json = dump(evidence)
        _audit_pending(
            db,
            "integration:greenbone",
            event_type,
            "remediation_evidence",
            item.id,
            {
                "finding_id": item.finding_id,
                "campaign_id": item.campaign_id,
                "job_id": item.job_id,
                "report_id": item.rescan_report_id,
                "cve": item.cve,
                "detected": detected,
            },
        )

    if items:
        db.commit()

    return {
        "verified": verified,
        "still_detected": still_detected,
        "waiting": waiting,
    }


def run_greenbone_sync():
    if not GREENBONE_SYNC_LOCK.acquire(blocking=False):
        raise RuntimeError("Greenbone sync is already running")

    db = SessionLocal()
    state = integration_state(db, "greenbone")
    config_obj = get_greenbone_config()
    config = public_greenbone_config(config_obj)
    try:
        state.enabled = config["enabled"]
        state.status = "running"
        state.last_attempt_at = now()
        state.last_error = ""
        db.commit()

        data = fetch_greenbone_findings(config_obj)
        report_ids = [item["report_id"] for item in data["reports"]]
        scan_id = report_ids[0] if len(report_ids) == 1 else f"multi:{len(report_ids)}"
        stats = upsert_vulnerability_findings(db, "openvas", scan_id, data["findings"])
        remediation = reconcile_remediation_evidence(db, data["reports"])
        not_detected = 0
        if config_obj.reconcile_absent:
            not_detected = reconcile_greenbone_absent(db, data["reports"])

        details = {
            "manager_version": data.get("manager_version", ""),
            "reports": len(data["reports"]),
            "findings": len(data["findings"]),
            "created": stats["created"],
            "updated": stats["updated"],
            "matched": stats["matched"],
            "not_detected": not_detected,
            "remediation_verified": remediation["verified"],
            "remediation_still_detected": remediation["still_detected"],
            "remediation_waiting": remediation["waiting"],
        }
        state.status = "ok"
        state.last_success_at = now()
        state.last_error = ""
        state.details_json = dump(details)
        db.commit()
        capture_asset_risk_snapshots(db, source="greenbone_sync")
        capture_remediation_project_snapshots(db, source="greenbone_sync")
        audit(db, "integration:greenbone", "greenbone.sync.success", "integration", "greenbone", details)
        return details
    except Exception as exc:
        state.status = "error"
        state.last_error = str(exc)[:2000]
        db.commit()
        audit(
            db,
            "integration:greenbone",
            "greenbone.sync.failed",
            "integration",
            "greenbone",
            {"error": str(exc)[:1000]},
        )
        raise
    finally:
        db.close()
        GREENBONE_SYNC_LOCK.release()


def run_threat_intel_sync():
    if not THREAT_INTEL_SYNC_LOCK.acquire(blocking=False):
        raise RuntimeError("threat intel sync is already running")

    db = SessionLocal()
    state = integration_state(db, "threat_intel")
    config = get_threat_intel_config()
    public = public_threat_intel_config(config)
    try:
        state.enabled = public["enabled"]
        state.status = "running"
        state.last_attempt_at = now()
        state.last_error = ""
        db.commit()

        findings = db.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.status == "open",
            VulnerabilityFinding.cve != "",
        ).all()
        cves = sorted({finding.cve.upper() for finding in findings if finding.cve})
        epss_data = {}
        kev_data = {}
        errors = {}

        try:
            epss_data = fetch_epss(cves, config)
        except Exception as exc:
            errors["epss"] = str(exc)[:1000]

        try:
            kev_data = fetch_kev(config)
        except Exception as exc:
            errors["kev"] = str(exc)[:1000]

        if len(errors) == 2:
            raise RuntimeError(
                "threat intel sources failed: "
                + "; ".join(f"{name}: {message}" for name, message in sorted(errors.items()))
            )

        updated = 0
        epss_enriched = 0
        kev_enriched = 0
        timestamp = now().isoformat()

        for finding in findings:
            cve = finding.cve.upper()
            raw = load(finding.raw_json, {})
            threat = raw.get("threat_intel") if isinstance(raw.get("threat_intel"), dict) else {}

            if "epss" not in errors:
                epss_row = epss_data.get(cve)
                if epss_row:
                    threat.update(epss_row)
                    epss_enriched += 1
                else:
                    for key in ("epss", "epss_percentile", "epss_date"):
                        threat.pop(key, None)

            if "kev" not in errors:
                kev_row = kev_data.get(cve)
                if kev_row:
                    threat.update(kev_row)
                    kev_enriched += 1
                else:
                    threat["kev"] = False
                    for key in (
                        "kev_date_added",
                        "kev_due_date",
                        "kev_vendor_project",
                        "kev_product",
                        "kev_required_action",
                        "kev_ransomware_use",
                    ):
                        threat.pop(key, None)

            threat["updated_at"] = timestamp
            threat["sources"] = {
                "epss": "FIRST EPSS",
                "kev": "CISA KEV",
            }
            raw["threat_intel"] = threat
            finding.raw_json = dump(raw)
            updated += 1

        details = {
            "findings_considered": len(findings),
            "unique_cves": len(cves),
            "updated": updated,
            "epss_enriched": epss_enriched,
            "kev_enriched": kev_enriched,
            "source_errors": errors,
        }
        state.status = "degraded" if errors else "ok"
        state.last_success_at = now()
        state.last_error = "; ".join(
            f"{name}: {message}" for name, message in sorted(errors.items())
        )
        state.details_json = dump(details)
        db.commit()
        capture_asset_risk_snapshots(db, source="threat_intel_sync")
        audit(
            db,
            "integration:threat_intel",
            "threat_intel.sync.success",
            "integration",
            "threat_intel",
            details,
        )
        return details
    except Exception as exc:
        state.status = "error"
        state.last_error = str(exc)[:2000]
        db.commit()
        audit(
            db,
            "integration:threat_intel",
            "threat_intel.sync.failed",
            "integration",
            "threat_intel",
            {"error": str(exc)[:1000]},
        )
        raise
    finally:
        db.close()
        THREAT_INTEL_SYNC_LOCK.release()


def threat_intel_worker():
    config = get_threat_intel_config()
    if not config.enabled:
        return
    next_sync_at = now()
    while not THREAT_INTEL_STOP.wait(30):
        current = now()
        if current < next_sync_at:
            continue
        try:
            run_threat_intel_sync()
        except Exception:
            pass
        next_sync_at = now() + timedelta(seconds=get_threat_intel_config().interval_seconds)


@app.on_event("startup")
def start_threat_intel_worker():
    if get_threat_intel_config().enabled:
        thread = threading.Thread(target=threat_intel_worker, name="threat-intel-sync", daemon=True)
        thread.start()


@app.on_event("shutdown")
def stop_threat_intel_worker():
    THREAT_INTEL_STOP.set()


def greenbone_worker():
    config = get_greenbone_config()
    if not config.enabled:
        return

    next_sync_at = now()
    while not GREENBONE_STOP.wait(30):
        try:
            process_ready_remediation_rescans()
        except Exception:
            pass

        db = SessionLocal()
        try:
            active_rescans = remediation_scan_active_count(db)
        finally:
            db.close()

        current = now()
        if current < next_sync_at and not active_rescans:
            continue

        try:
            run_greenbone_sync()
        except Exception:
            pass

        interval = 60 if active_rescans else get_greenbone_config().interval_seconds
        next_sync_at = now() + timedelta(seconds=interval)


@app.on_event("startup")
def start_greenbone_worker():
    if get_greenbone_config().enabled:
        thread = threading.Thread(target=greenbone_worker, name="greenbone-sync", daemon=True)
        thread.start()


@app.on_event("shutdown")
def stop_greenbone_worker():
    GREENBONE_STOP.set()

def parse_clock(value: str) -> int:
    try:
        hour_text, minute_text = value.split(":", 1)
        hour = int(hour_text)
        minute = int(minute_text)
    except Exception as exc:
        raise ValueError("time must use HH:MM") from exc
    if not 0 <= hour <= 23 or not 0 <= minute <= 59:
        raise ValueError("time must use HH:MM")
    return hour * 60 + minute


def maintenance_window_state(payload: dict, instant=None):
    start_text = str(payload.get("maintenance_start") or "").strip()
    end_text = str(payload.get("maintenance_end") or "").strip()
    timezone_name = str(payload.get("maintenance_timezone") or "UTC").strip() or "UTC"

    if not start_text and not end_text:
        return {
            "enabled": False,
            "eligible_now": True,
            "reason": "maintenance window disabled",
            "timezone": timezone_name,
            "start": "",
            "end": "",
            "days": [],
        }

    if not start_text or not end_text:
        return {
            "enabled": True,
            "eligible_now": False,
            "reason": "maintenance window is incomplete",
            "timezone": timezone_name,
            "start": start_text,
            "end": end_text,
            "days": payload.get("maintenance_days") or [],
        }

    try:
        start = parse_clock(start_text)
        end = parse_clock(end_text)
        zone = ZoneInfo(timezone_name)
    except (ValueError, ZoneInfoNotFoundError):
        return {
            "enabled": True,
            "eligible_now": False,
            "reason": "invalid maintenance window",
            "timezone": timezone_name,
            "start": start_text,
            "end": end_text,
            "days": payload.get("maintenance_days") or [],
        }

    days = payload.get("maintenance_days")
    if not isinstance(days, list) or not days:
        days = list(range(7))
    days = sorted({int(day) for day in days if isinstance(day, int) or str(day).isdigit()})
    days = [day for day in days if 0 <= day <= 6]

    current = (instant or now()).astimezone(zone)
    minute = current.hour * 60 + current.minute
    weekday = current.weekday()

    if start == end:
        eligible = weekday in days
    elif start < end:
        eligible = weekday in days and start <= minute < end
    elif minute >= start:
        eligible = weekday in days
    elif minute < end:
        eligible = ((weekday - 1) % 7) in days
    else:
        eligible = False

    return {
        "enabled": True,
        "eligible_now": eligible,
        "reason": "inside maintenance window" if eligible else "outside maintenance window",
        "timezone": timezone_name,
        "start": start_text,
        "end": end_text,
        "days": days,
        "local_time": current.isoformat(),
    }


def validate_campaign_policy(body):
    if body.reboot_policy not in {"never", "if_required"}:
        raise HTTPException(status_code=400, detail="unsupported reboot policy")

    start = body.maintenance_start.strip()
    end = body.maintenance_end.strip()
    if bool(start) != bool(end):
        raise HTTPException(status_code=400, detail="maintenance start and end must be provided together")

    if start:
        try:
            parse_clock(start)
            parse_clock(end)
            ZoneInfo(body.maintenance_timezone)
        except (ValueError, ZoneInfoNotFoundError) as exc:
            raise HTTPException(status_code=400, detail=f"invalid maintenance window: {exc}") from exc

        if not body.maintenance_days:
            raise HTTPException(status_code=400, detail="maintenance days cannot be empty")
        if any(day < 0 or day > 6 for day in body.maintenance_days):
            raise HTTPException(status_code=400, detail="maintenance days must be between 0 and 6")

    service_re = re.compile(r"^[A-Za-z0-9_.@:-]{1,128}$")
    normalized_services = []
    for service in body.critical_services:
        service = str(service or "").strip()
        if not service_re.fullmatch(service):
            raise HTTPException(status_code=400, detail=f"invalid critical service name: {service}")
        normalized_services.append(service)
    if len(set(normalized_services)) != len(normalized_services):
        raise HTTPException(status_code=400, detail="critical services must be unique")

    check_names = set()
    for check in body.application_health_checks:
        name = check.name.strip()
        if name in check_names:
            raise HTTPException(status_code=400, detail=f"duplicate application health check name: {name}")
        check_names.add(name)

        parsed = urlparse(check.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise HTTPException(status_code=400, detail=f"invalid application health URL for {name}")
        if parsed.username or parsed.password:
            raise HTTPException(status_code=400, detail=f"credentials are not allowed in application health URL for {name}")

        hostname = parsed.hostname.lower()
        loopback = hostname == "localhost"
        if not loopback:
            try:
                loopback = ipaddress.ip_address(hostname).is_loopback
            except ValueError:
                loopback = False
        if not loopback:
            raise HTTPException(
                status_code=400,
                detail=f"application health URL for {name} must target localhost or a loopback address",
            )


def health_policy_from_campaign(body) -> dict:
    return {
        "enabled": bool(body.health_gate_enabled),
        "required": bool(body.health_gate_require_telemetry),
        "cpu_max_percent": float(body.health_cpu_max_percent),
        "cpu_max_delta": float(body.health_cpu_max_delta),
        "memory_max_percent": float(body.health_memory_max_percent),
        "memory_max_delta": float(body.health_memory_max_delta),
        "disk_min_free_percent": float(body.health_disk_min_free_percent),
        "disk_max_free_drop": float(body.health_disk_max_free_drop),
        "critical_services": [str(item).strip() for item in body.critical_services],
        "application_checks": [item.model_dump() for item in body.application_health_checks],
        "policy_ttl_seconds": 86400,
    }


def _number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def evaluate_health_regression(policy: dict, baseline: dict, current: dict):
    if not policy.get("enabled"):
        return {"status": "disabled", "issues": [], "reason": "health telemetry gate disabled"}

    required = bool(policy.get("required", True))
    if not baseline:
        return {
            "status": "failed" if required else "skipped",
            "issues": ["pre-patch health baseline unavailable"] if required else [],
            "reason": "pre-patch health baseline unavailable",
        }
    if not current:
        return {
            "status": "waiting" if required else "skipped",
            "issues": [],
            "reason": "waiting for post-patch health telemetry",
        }

    issues = []
    comparisons = {}

    baseline_cpu = _number(baseline.get("cpu_percent"))
    current_cpu = _number(current.get("cpu_percent"))
    if required and (baseline_cpu is None or current_cpu is None):
        issues.append("CPU telemetry unavailable")
    elif baseline_cpu is not None and current_cpu is not None:
        delta = round(current_cpu - baseline_cpu, 2)
        comparisons["cpu"] = {"baseline": baseline_cpu, "current": current_cpu, "delta": delta}
        if current_cpu > float(policy.get("cpu_max_percent", 95.0)):
            issues.append(f"CPU {current_cpu:.1f}% exceeds {float(policy.get('cpu_max_percent', 95.0)):.1f}%")
        if delta > float(policy.get("cpu_max_delta", 40.0)):
            issues.append(f"CPU increased {delta:.1f} percentage points")

    baseline_memory = _number(baseline.get("memory_percent"))
    current_memory = _number(current.get("memory_percent"))
    if required and (baseline_memory is None or current_memory is None):
        issues.append("memory telemetry unavailable")
    elif baseline_memory is not None and current_memory is not None:
        delta = round(current_memory - baseline_memory, 2)
        comparisons["memory"] = {"baseline": baseline_memory, "current": current_memory, "delta": delta}
        if current_memory > float(policy.get("memory_max_percent", 95.0)):
            issues.append(f"memory {current_memory:.1f}% exceeds {float(policy.get('memory_max_percent', 95.0)):.1f}%")
        if delta > float(policy.get("memory_max_delta", 20.0)):
            issues.append(f"memory increased {delta:.1f} percentage points")

    baseline_disk = _number((baseline.get("disk") or {}).get("free_percent"))
    current_disk = _number((current.get("disk") or {}).get("free_percent"))
    if required and (baseline_disk is None or current_disk is None):
        issues.append("disk telemetry unavailable")
    elif baseline_disk is not None and current_disk is not None:
        drop = round(baseline_disk - current_disk, 2)
        comparisons["disk_free"] = {"baseline": baseline_disk, "current": current_disk, "drop": drop}
        if current_disk < float(policy.get("disk_min_free_percent", 5.0)):
            issues.append(f"disk free {current_disk:.1f}% is below minimum")
        if drop > float(policy.get("disk_max_free_drop", 10.0)):
            issues.append(f"disk free dropped {drop:.1f} percentage points")

    baseline_services = baseline.get("services") if isinstance(baseline.get("services"), dict) else {}
    current_services = current.get("services") if isinstance(current.get("services"), dict) else {}
    service_results = {}
    for name in policy.get("critical_services") or []:
        before = baseline_services.get(name) if isinstance(baseline_services.get(name), dict) else {}
        after = current_services.get(name) if isinstance(current_services.get(name), dict) else {}
        healthy = bool(after.get("healthy", False))
        service_results[name] = {
            "baseline_healthy": bool(before.get("healthy", False)),
            "current_healthy": healthy,
            "status": str(after.get("status") or "unknown"),
        }
        if not healthy:
            issues.append(f"critical service {name} is not healthy")
    if service_results:
        comparisons["services"] = service_results

    baseline_apps = baseline.get("applications") if isinstance(baseline.get("applications"), dict) else {}
    current_apps = current.get("applications") if isinstance(current.get("applications"), dict) else {}
    app_results = {}
    for check in policy.get("application_checks") or []:
        name = str(check.get("name") or "")
        before = baseline_apps.get(name) if isinstance(baseline_apps.get(name), dict) else {}
        after = current_apps.get(name) if isinstance(current_apps.get(name), dict) else {}
        healthy = bool(after.get("healthy", False))
        app_results[name] = {
            "baseline_healthy": bool(before.get("healthy", False)),
            "current_healthy": healthy,
            "status_code": after.get("status_code"),
            "latency_ms": after.get("latency_ms"),
        }
        if not healthy:
            issues.append(f"application health check {name} failed")
    if app_results:
        comparisons["applications"] = app_results

    if issues:
        return {
            "status": "failed",
            "reason": "post-patch health regression or unhealthy critical check",
            "issues": issues,
            "comparisons": comparisons,
        }

    return {
        "status": "passed",
        "reason": "post-patch health telemetry is within policy",
        "issues": [],
        "comparisons": comparisons,
    }



def rollback_state(job: PatchJob):
    if job.action == "rollback_checkpoint":
        payload=load(job.payload_json,{})
        return {
            "status":"rollback_job",
            "original_job_id":payload.get("_rollback_of_job_id",""),
            "method":payload.get("method",""),
        }

    if job.action != "install_updates":
        return {"status":"unavailable","reason":"rollback applies only to install jobs"}
    if job.status != "success":
        return {"status":"not_ready","reason":"install job has not completed successfully"}

    result=load(job.result_json,{})
    checkpoint=result.get("rollback_checkpoint") or {}
    if checkpoint.get("status") != "created":
        return {
            "status":"unavailable",
            "reason":checkpoint.get("reason") or "no rollback checkpoint was created",
            "checkpoint":checkpoint,
        }

    existing=[]
    if job.campaign:
        for candidate in job.campaign.jobs:
            if candidate.action != "rollback_checkpoint":
                continue
            payload=load(candidate.payload_json,{})
            if payload.get("_rollback_of_job_id") == job.id:
                existing.append(candidate)
    if existing:
        current=sorted(existing,key=lambda item:item.created_at)[-1]
        mapped="completed" if current.status == "success" else "rollback_failed" if current.status == "failed" else "requested"
        return {
            "status":mapped,
            "rollback_job_id":current.id,
            "rollback_job_status":current.status,
            "checkpoint":checkpoint,
        }

    if not checkpoint.get("automatic_restore"):
        return {
            "status":"manual_only",
            "reason":"checkpoint exists but automated restore is not supported",
            "checkpoint":checkpoint,
        }

    return {
        "status":"eligible",
        "reason":"manual approval required",
        "checkpoint":checkpoint,
    }


def job_post_patch_validation(job: PatchJob):
    payload = load(job.payload_json, {})

    if job.action == "activate_agent_update":
        if job.status != "success":
            return {"status": "waiting", "reason": "agent activation job has not succeeded"}

        agent = job.agent
        if not agent:
            return {"status": "failed", "reason": "agent unavailable"}

        expected_version = str(payload.get("expected_version") or "")
        inventory = load(agent.inventory_json, {})
        activation = inventory.get("activation") if isinstance(inventory.get("activation"), dict) else {}
        update_state = inventory.get("update") if isinstance(inventory.get("update"), dict) else {}
        activation_status = str(activation.get("status") or "")

        if (
            update_state.get("status") == "quarantined"
            and str(update_state.get("quarantined_version") or update_state.get("staged_version") or "") == expected_version
        ):
            return {
                "status": "failed",
                "reason": "agent release entered quarantine after watchdog rollback",
                "activation": activation,
            }

        if activation_status == "rolled_back" and str(activation.get("target_version") or "") == expected_version:
            return {
                "status": "failed",
                "reason": "agent update was rolled back by watchdog",
                "activation": activation,
            }

        if activation_status in {"aborted_before_switch", "error"} and str(activation.get("target_version") or "") == expected_version:
            return {
                "status": "failed",
                "reason": "agent update activation failed",
                "activation": activation,
            }

        runtime = agent_runtime_metadata(agent)
        committed = (
            activation_status == "committed"
            and str(activation.get("confirmed_version") or "") == expected_version
            and str(runtime.get("version") or "") == expected_version
        )
        if not committed and job.finished_at:
            finished = job.finished_at
            if finished.tzinfo is None:
                finished = finished.replace(tzinfo=timezone.utc)
            elapsed = (now() - finished).total_seconds()
            if elapsed > AGENT_ACTIVATION_CONFIRM_TIMEOUT_SECONDS:
                return {
                    "status": "failed",
                    "reason": "agent activation confirmation timed out",
                    "timeout_seconds": AGENT_ACTIVATION_CONFIRM_TIMEOUT_SECONDS,
                    "elapsed_seconds": int(elapsed),
                    "activation": activation,
                }

        if committed:
            if job.finished_at and agent.last_seen:
                finished = job.finished_at
                last_seen = agent.last_seen
                if finished.tzinfo is None:
                    finished = finished.replace(tzinfo=timezone.utc)
                if last_seen.tzinfo is None:
                    last_seen = last_seen.replace(tzinfo=timezone.utc)
                if last_seen <= finished:
                    return {
                        "status": "waiting",
                        "reason": "waiting for fresh heartbeat from activated agent",
                        "activation": activation,
                    }
            return {
                "status": "passed",
                "reason": "agent update committed and confirmed by heartbeat",
                "activation": activation,
            }

        return {
            "status": "waiting",
            "reason": "waiting for agent activation heartbeat confirmation",
            "activation": activation,
        }

    if job.action != "install_updates" or not payload.get("post_patch_validation", True):
        return {"status": "disabled", "reason": "post-patch validation disabled"}

    if job.status != "success":
        return {"status": "waiting", "reason": "job has not succeeded"}

    agent = job.agent
    if not agent:
        return {"status": "failed", "reason": "agent unavailable"}

    if not job.finished_at:
        return {"status": "waiting", "reason": "job completion timestamp unavailable"}

    finished = job.finished_at
    if finished.tzinfo is None:
        finished = finished.replace(tzinfo=timezone.utc)

    last_seen = agent.last_seen
    if not last_seen:
        return {"status": "waiting", "reason": "waiting for post-patch heartbeat"}
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    if last_seen <= finished:
        return {"status": "waiting", "reason": "waiting for fresh post-patch heartbeat"}

    if agent.reboot_required:
        return {"status": "waiting", "reason": "reboot is still required"}

    baseline_pending = int(payload.get("_baseline_pending_updates", agent.pending_updates))
    baseline_critical = int(payload.get("_baseline_critical_updates", agent.critical_updates))

    if agent.critical_updates > baseline_critical:
        return {
            "status": "failed",
            "reason": "critical updates increased after patching",
            "baseline_critical": baseline_critical,
            "current_critical": agent.critical_updates,
        }

    if agent.pending_updates > baseline_pending:
        return {
            "status": "failed",
            "reason": "pending updates increased after patching",
            "baseline_pending": baseline_pending,
            "current_pending": agent.pending_updates,
        }

    health_policy = payload.get("health_policy") if isinstance(payload.get("health_policy"), dict) else {}
    health_result = {"status": "disabled", "reason": "health telemetry gate disabled", "issues": []}
    if health_policy.get("enabled"):
        job_result = load(job.result_json, {})
        baseline_health = job_result.get("health_baseline") if isinstance(job_result.get("health_baseline"), dict) else {}
        inventory = load(agent.inventory_json, {})
        current_health = inventory.get("health") if isinstance(inventory.get("health"), dict) else {}

        if current_health:
            collected_text = str(current_health.get("collected_at") or "")
            try:
                collected_at = datetime.fromisoformat(collected_text.replace("Z", "+00:00"))
                if collected_at.tzinfo is None:
                    collected_at = collected_at.replace(tzinfo=timezone.utc)
                if collected_at <= finished:
                    current_health = {}
            except ValueError:
                if health_policy.get("required", True):
                    current_health = {}

        health_result = evaluate_health_regression(health_policy, baseline_health, current_health)
        if health_result["status"] == "failed":
            return {
                "status": "failed",
                "reason": health_result["reason"],
                "health_validation": health_result,
                "baseline_pending": baseline_pending,
                "current_pending": agent.pending_updates,
                "baseline_critical": baseline_critical,
                "current_critical": agent.critical_updates,
            }
        if health_result["status"] == "waiting":
            return {
                "status": "waiting",
                "reason": health_result["reason"],
                "health_validation": health_result,
            }

    return {
        "status": "passed",
        "reason": "fresh heartbeat received with no patch or health regression",
        "baseline_pending": baseline_pending,
        "current_pending": agent.pending_updates,
        "baseline_critical": baseline_critical,
        "current_critical": agent.critical_updates,
        "health_validation": health_result,
    }


def ring_bucket(agent_id: str) -> int:
    return int(hashlib.sha256(agent_id.encode()).hexdigest()[:8], 16) % 10000


def campaign_ring_jobs(c: Campaign):
    marked = [
        job for job in c.jobs
        if job.action in {"scan_updates", "install_updates", "activate_agent_update"}
        and int(load(job.payload_json, {}).get("_ring_percent", -1)) == int(c.ring_percent)
    ]
    return marked if marked else list(c.jobs)



def campaign_health(c: Campaign):
    jobs = campaign_ring_jobs(c)
    counts = {"pending": 0, "blocked": 0, "claimed": 0, "running": 0, "stalled": 0, "success": 0, "failed": 0, "skipped": 0}
    validations = {"passed": 0, "waiting": 0, "failed": 0, "disabled": 0}
    validation_details = []

    for job in jobs:
        counts[job.status] = counts.get(job.status, 0) + 1
        if job.status == "success":
            validation = job_post_patch_validation(job)
            status = validation.get("status", "waiting")
            validations[status] = validations.get(status, 0) + 1
            if status in {"waiting", "failed"}:
                validation_details.append({
                    "job_id": job.id,
                    "agent_id": job.agent_id,
                    "hostname": job.agent.hostname if job.agent else "",
                    **validation,
                })

    active = counts["pending"] + counts["blocked"] + counts["claimed"] + counts["running"] + counts["stalled"]
    terminal = counts["success"] + counts["failed"] + counts["skipped"]
    success_rate = round((counts["success"] / terminal * 100), 1) if terminal else 0.0
    rollout_governance = load(c.payload_json, {}).get("rollout_governance")
    rollout_governance = rollout_governance if isinstance(rollout_governance, dict) else {}
    configured_min_success = float(rollout_governance.get("promotion_min_success_rate", 90.0) or 90.0)
    required_success_rate = 100.0 if c.action == "activate_agent_update" else configured_min_success
    validation_blocked = validations["failed"] > 0 or validations["waiting"] > 0
    ready = (
        bool(jobs)
        and active == 0
        and terminal == len(jobs)
        and success_rate >= required_success_rate
        and not validation_blocked
    )

    if not jobs:
        reason = "no jobs in current ring"
    elif counts["stalled"]:
        reason = "current ring has stalled jobs"
    elif counts["blocked"]:
        reason = "current ring has compatibility-blocked jobs"
    elif active:
        reason = "current ring still has active jobs"
    elif terminal != len(jobs):
        reason = "current ring has non-terminal jobs"
    elif success_rate < required_success_rate:
        reason = "success rate below required threshold"
    elif validations["failed"]:
        reason = "post-patch validation failed"
    elif validations["waiting"]:
        reason = "waiting for post-patch validation"
    else:
        reason = "healthy"

    return {
        "ring_percent": c.ring_percent,
        "jobs": len(jobs),
        "counts": counts,
        "active": active,
        "terminal": terminal,
        "success_rate": success_rate,
        "required_success_rate": required_success_rate,
        "validation": validations,
        "validation_details": validation_details[:20],
        "ready": ready,
        "reason": reason,
    }




def campaign_ring_summary(c: Campaign, ring_percent: int) -> dict:
    jobs = [
        job for job in c.jobs
        if int(load(job.payload_json, {}).get("_ring_percent", -1)) == int(ring_percent)
    ]
    counts = {"pending": 0, "blocked": 0, "claimed": 0, "running": 0, "stalled": 0, "success": 0, "failed": 0, "skipped": 0}
    validations = {"passed": 0, "waiting": 0, "failed": 0, "disabled": 0}
    durations = []
    for job in jobs:
        counts[job.status] = counts.get(job.status, 0) + 1
        if job.status == "success":
            validation = job_post_patch_validation(job)
            status = validation.get("status", "waiting")
            validations[status] = validations.get(status, 0) + 1
        if job.started_at and job.finished_at:
            started = job.started_at if job.started_at.tzinfo else job.started_at.replace(tzinfo=timezone.utc)
            finished = job.finished_at if job.finished_at.tzinfo else job.finished_at.replace(tzinfo=timezone.utc)
            durations.append(max(0.0, (finished - started).total_seconds()))
    terminal = counts["success"] + counts["failed"] + counts["skipped"]
    success_rate = round((counts["success"] / terminal * 100), 1) if terminal else 0.0
    failure_rate = round((counts["failed"] / terminal * 100), 1) if terminal else 0.0
    avg_duration = round(sum(durations) / len(durations), 1) if durations else None
    return {
        "ring_percent": int(ring_percent),
        "jobs": len(jobs),
        "counts": counts,
        "terminal": terminal,
        "success_rate": success_rate,
        "failure_rate": failure_rate,
        "validation": validations,
        "avg_duration_seconds": avg_duration,
    }


def campaign_regression_analysis(c: Campaign) -> dict:
    payload = load(c.payload_json, {})
    governance = payload.get("rollout_governance") if isinstance(payload.get("rollout_governance"), dict) else {}
    max_success_drop = float(governance.get("promotion_max_success_drop", 10.0) or 10.0)
    current = campaign_ring_summary(c, c.ring_percent)
    previous_rings = sorted({
        int(load(job.payload_json, {}).get("_ring_percent", -1))
        for job in c.jobs
        if 0 < int(load(job.payload_json, {}).get("_ring_percent", -1)) < int(c.ring_percent)
    })
    previous = campaign_ring_summary(c, previous_rings[-1]) if previous_rings else None
    reasons = []
    status = "NO_BASELINE"

    if previous:
        success_drop = round(previous["success_rate"] - current["success_rate"], 1)
        failure_rate_increase = round(current["failure_rate"] - previous["failure_rate"], 1)
        validation_failure_delta = int(current["validation"].get("failed", 0)) - int(previous["validation"].get("failed", 0))
        if success_drop > max_success_drop:
            reasons.append(f"success rate dropped {success_drop} p.p. versus previous ring")
        if failure_rate_increase > 0:
            reasons.append(f"failure rate increased {failure_rate_increase} p.p. versus previous ring")
        if validation_failure_delta > 0:
            reasons.append(f"post-patch validation failures increased by {validation_failure_delta}")
        status = "REGRESSION" if reasons else "STABLE"
    else:
        success_drop = None
        failure_rate_increase = None
        validation_failure_delta = None
        if current["jobs"]:
            reasons.append("first observed ring; no previous ring baseline")
        else:
            reasons.append("current ring has no jobs")

    return {
        "status": status,
        "reasons": reasons,
        "current": current,
        "previous": previous,
        "thresholds": {
            "max_success_rate_drop": max_success_drop,
        },
        "deltas": {
            "success_rate_drop": success_drop,
            "failure_rate_increase": failure_rate_increase,
            "validation_failure_delta": validation_failure_delta,
        },
    }


def campaign_rollout_governance(c: Campaign, reference: datetime | None = None) -> dict:
    reference = reference or now()
    payload = load(c.payload_json, {})
    governance = payload.get("rollout_governance") if isinstance(payload.get("rollout_governance"), dict) else {}
    raw_plan = governance.get("plan") if isinstance(governance.get("plan"), list) else []
    plan_enforced = bool(raw_plan)
    plan = sorted({
        int(value) for value in raw_plan
        if isinstance(value, (int, float)) and 1 <= int(value) <= 100
    })
    if not plan:
        plan = default_rollout_plan(c.ring_percent)
    if c.ring_percent not in plan:
        plan = sorted(set(plan + [c.ring_percent]))
    if plan[-1] != 100:
        plan.append(100)

    health = campaign_health(c)
    regression = campaign_regression_analysis(c)
    current_index = plan.index(c.ring_percent) if c.ring_percent in plan else 0
    next_ring = plan[current_index + 1] if current_index + 1 < len(plan) else None
    soak_minutes = max(0, int(governance.get("soak_minutes", 0) or 0))
    pause_on_failure = bool(governance.get("pause_on_failure", True))
    jobs = campaign_ring_jobs(c)
    terminal_finished = [
        job.finished_at if job.finished_at.tzinfo else job.finished_at.replace(tzinfo=timezone.utc)
        for job in jobs
        if job.finished_at is not None
    ]
    ring_completed_at = max(terminal_finished) if terminal_finished and health["active"] == 0 else None
    soak_until = ring_completed_at + timedelta(minutes=soak_minutes) if ring_completed_at else None
    soak_remaining_seconds = (
        max(0, int((soak_until - reference).total_seconds()))
        if soak_until and soak_until > reference else 0
    )

    if c.status != "deployed":
        state = "DRAFT"
        reason = "campaign not deployed"
    elif c.ring_percent >= 100:
        state = "COMPLETE"
        reason = "rollout reached 100%"
    elif health["counts"].get("failed", 0) > 0 and pause_on_failure:
        state = "PAUSE"
        reason = "current ring has failed jobs and pause_on_failure is enabled"
    elif regression["status"] == "REGRESSION":
        state = "PAUSE"
        reason = "regression detected versus previous ring"
    elif not health["ready"]:
        state = "RUNNING"
        reason = health["reason"]
    elif soak_remaining_seconds > 0:
        state = "SOAK"
        reason = "health gate passed; waiting for soak time"
    else:
        state = "PROMOTE"
        reason = "health gate passed and soak time elapsed"

    return {
        "state": state,
        "reason": reason,
        "plan": plan,
        "plan_enforced": plan_enforced,
        "current_ring": c.ring_percent,
        "next_ring": next_ring,
        "soak_minutes": soak_minutes,
        "ring_completed_at": ring_completed_at.isoformat() if ring_completed_at else None,
        "soak_until": soak_until.isoformat() if soak_until else None,
        "soak_remaining_seconds": soak_remaining_seconds,
        "pause_on_failure": pause_on_failure,
        "promotion_min_success_rate": float(governance.get("promotion_min_success_rate", 90.0) or 90.0),
        "promotion_max_success_drop": float(governance.get("promotion_max_success_drop", 10.0) or 10.0),
        "regression": regression,
        "recommendation": {
            "action": (
                "PROMOTE" if state == "PROMOTE"
                else "PAUSE" if state == "PAUSE"
                else "WAIT" if state in {"RUNNING", "SOAK"}
                else "COMPLETE" if state == "COMPLETE"
                else "REVIEW"
            ),
            "reasons": regression["reasons"] if regression["status"] == "REGRESSION" else [reason],
        },
        "health": health,
    }


def serialize_campaign_ring_decision(item: CampaignRingDecision) -> dict:
    return {
        "id": item.id,
        "campaign_id": item.campaign_id,
        "from_ring": item.from_ring,
        "to_ring": item.to_ring,
        "decision": item.decision,
        "reason": item.reason,
        "health": load(item.health_json, {}),
        "actor": item.actor,
        "created_at": item.created_at.isoformat() if item.created_at else None,
    }


def record_campaign_ring_decision(
    db: Session,
    campaign: Campaign,
    from_ring: int,
    to_ring: int,
    decision: str,
    reason: str,
    health: dict,
    actor: str,
):
    item = CampaignRingDecision(
        id=str(uuid.uuid4()),
        campaign_id=campaign.id,
        from_ring=int(from_ring),
        to_ring=int(to_ring),
        decision=decision,
        reason=reason,
        health_json=dump(health),
        actor=actor,
    )
    db.add(item)
    return item


def serialize_campaign_approval(c: Campaign) -> dict:
    payload = load(c.payload_json, {})
    required = bool(payload.get("approval_required", False))
    approval = c.approval
    if not required:
        return {"required": False, "status": "not_required"}
    if not approval:
        return {"required": True, "status": "missing"}
    return {
        "required": True,
        "status": approval.status,
        "request_reason": approval.request_reason,
        "requested_by": approval.requested_by,
        "requested_at": approval.requested_at.isoformat() if approval.requested_at else None,
        "decided_by": approval.decided_by,
        "decision_reason": approval.decision_reason,
        "decided_at": approval.decided_at.isoformat() if approval.decided_at else None,
    }


def serialize_campaign(c: Campaign):
    counts = {"pending": 0, "blocked": 0, "claimed": 0, "running": 0, "success": 0, "failed": 0, "skipped": 0}
    for j in c.jobs:
        counts[j.status] = counts.get(j.status, 0) + 1
    return {
        "id": c.id,
        "name": c.name,
        "description": c.description,
        "target_os": c.target_os,
        "target_tag": c.target_tag,
        "ring_percent": c.ring_percent,
        "action": c.action,
        "payload": load(c.payload_json, {}),
        "not_before": c.not_before.isoformat() if c.not_before else None,
        "allow_reboot": c.allow_reboot,
        "status": c.status,
        "created_at": c.created_at.isoformat(),
        "job_counts": counts,
        "jobs_total": len(c.jobs),
        "health": campaign_health(c),
        "rollout_governance": campaign_rollout_governance(c),
        "rollout_complete": c.ring_percent >= 100,
        "approval": serialize_campaign_approval(c),
    }


def serialize_job(j: PatchJob, claim_token: str | None = None):
    data = {
        "id": j.id,
        "campaign_id": j.campaign_id,
        "campaign_name": j.campaign.name if j.campaign else "",
        "agent_id": j.agent_id,
        "hostname": j.agent.hostname if j.agent else "",
        "action": j.action,
        "payload": load(j.payload_json, {}),
        "status": j.status,
        "not_before": j.not_before.isoformat() if j.not_before else None,
        "claimed_at": j.claimed_at.isoformat() if j.claimed_at else None,
        "started_at": j.started_at.isoformat() if j.started_at else None,
        "finished_at": j.finished_at.isoformat() if j.finished_at else None,
        "result": load(j.result_json, {}),
        "error": j.error,
        "validation": job_post_patch_validation(j),
        "maintenance_window": maintenance_window_state(load(j.payload_json, {})),
        "rollback": rollback_state(j),
        "lease_expires_at": j.lease_expires_at.isoformat() if j.lease_expires_at else None,
        "last_lease_at": j.last_lease_at.isoformat() if j.last_lease_at else None,
        "attempt_count": j.attempt_count,
        "agent_compatibility": job_agent_compatibility(j),
        "remediation": (
            serialize_remediation_evidence(j.remediation_evidence)
            if j.remediation_evidence
            else None
        ),
    }
    if claim_token is not None:
        data["claim_token"] = claim_token
        data["lease_seconds"] = JOB_CLAIM_LEASE_SECONDS
    return data



def _job_claim_matches(job: PatchJob, claim_token: str) -> bool:
    if not job.claim_token_hash:
        return not claim_token
    if not claim_token:
        return False
    return hmac.compare_digest(job.claim_token_hash, hash_token(claim_token))


def _audit_pending(db: Session, actor: str, event_type: str, object_type: str, object_id: str, details=None):
    db.add(AuditEvent(
        actor=actor,
        event_type=event_type,
        object_type=object_type,
        object_id=object_id,
        details_json=dump(details or {}),
    ))



def _approval_expiry(payload: dict):
    text = str(payload.get("approval_expires_at") or "")
    if not text:
        return None
    try:
        value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


def agent_update_authorization_check(job: PatchJob, agent: Agent, instant=None) -> tuple[bool, str]:
    if job.action != "activate_agent_update":
        return True, "not_agent_activation"

    payload = load(job.payload_json, {})
    current = instant or now()
    expiry = _approval_expiry(payload)
    if not expiry:
        return False, "approval_expiry_missing"
    if current >= expiry:
        return False, "approval_expired"

    binding = payload.get("release_binding")
    if not isinstance(binding, dict):
        return False, "release_binding_missing"

    expected_version = str(payload.get("expected_version") or "")
    if str(binding.get("version") or "") != expected_version:
        return False, "release_binding_version_mismatch"

    matches, reason = staged_release_binding_matches(agent, binding)
    if not matches:
        return False, reason

    try:
        current_binding = signed_release_binding(expected_version)
    except HTTPException:
        return False, "published_release_unavailable"

    for key in ("version", "artifact_sha256", "source_commit", "signing_key_id"):
        if str(current_binding.get(key) or "").lower() != str(binding.get(key) or "").lower():
            return False, "published_release_changed"

    return True, "authorized"


def invalidate_agent_update_authorization(db: Session, job: PatchJob, reason: str):
    job.status = "skipped"
    job.error = f"agent update authorization invalidated: {reason}"
    job.finished_at = now()
    job.claimed_at = None
    job.claim_token_hash = ""
    job.lease_expires_at = None
    job.last_lease_at = None
    _audit_pending(
        db,
        "system",
        "agent.update.authorization.invalidated",
        "job",
        job.id,
        {
            "agent_id": job.agent_id,
            "reason": reason,
            "expected_version": load(job.payload_json, {}).get("expected_version", ""),
        },
    )
    db.commit()


def compatibility_block_reason(result: dict) -> str:
    status = str(result.get("status") or "unknown")
    missing = result.get("missing_capabilities") or []
    runtime = result.get("agent") or {}
    parts = [f"agent compatibility blocked: {status}"]
    if runtime.get("version"):
        parts.append(f"version={runtime['version']}")
    if runtime.get("protocol"):
        parts.append(f"protocol={runtime['protocol']}")
    if missing:
        parts.append("missing=" + ",".join(missing))
    return "; ".join(parts)[:2000]


def block_incompatible_job(db: Session, job: PatchJob, agent: Agent) -> bool:
    if not AGENT_ENFORCE_COMPATIBILITY:
        return False

    result = job_agent_compatibility(job, agent)
    if result.get("compatible"):
        return False

    job.status = "blocked"
    job.error = compatibility_block_reason(result)
    job.claimed_at = None
    job.claim_token_hash = ""
    job.lease_expires_at = None
    job.last_lease_at = None

    _audit_pending(
        db,
        "system",
        "job.compatibility.blocked",
        "job",
        job.id,
        {
            "agent_id": agent.id,
            "compatibility_status": result.get("status"),
            "agent_version": (result.get("agent") or {}).get("version", ""),
            "agent_protocol": (result.get("agent") or {}).get("protocol", 0),
            "required_capabilities": result.get("required_capabilities") or [],
            "missing_capabilities": result.get("missing_capabilities") or [],
        },
    )
    return True


def reconcile_blocked_agent_jobs(db: Session, agent: Agent) -> int:
    if not AGENT_ENFORCE_COMPATIBILITY:
        return 0

    changed = 0
    jobs = db.query(PatchJob).filter(
        PatchJob.agent_id == agent.id,
        PatchJob.status == "blocked",
    ).order_by(PatchJob.created_at.asc()).all()

    for job in jobs:
        if not str(job.error or "").startswith("agent compatibility blocked:"):
            continue

        result = job_agent_compatibility(job, agent)
        if not result.get("compatible"):
            job.error = compatibility_block_reason(result)
            continue

        job.status = "pending"
        job.error = ""
        changed += 1
        _audit_pending(
            db,
            "system",
            "job.compatibility.unblocked",
            "job",
            job.id,
            {
                "agent_id": agent.id,
                "agent_version": (result.get("agent") or {}).get("version", ""),
                "agent_protocol": (result.get("agent") or {}).get("protocol", 0),
            },
        )

    if changed:
        db.commit()
    return changed



def sweep_expired_job_leases(db: Session, agent_id: str | None = None):
    t = now()
    q = db.query(PatchJob).filter(
        PatchJob.status.in_(["claimed", "running"]),
        PatchJob.lease_expires_at.is_not(None),
        PatchJob.lease_expires_at < t,
    )
    if agent_id:
        q = q.filter(PatchJob.agent_id == agent_id)

    expired = q.all()
    requeued = 0
    stalled = 0
    for job in expired:
        if job.status == "claimed":
            job.status = "pending"
            job.claimed_at = None
            job.claim_token_hash = ""
            job.lease_expires_at = None
            job.last_lease_at = None
            requeued += 1
            _audit_pending(
                db,
                "system",
                "job.claim.expired",
                "job",
                job.id,
                {"attempt_count": job.attempt_count, "action": job.action},
            )
        else:
            job.status = "stalled"
            job.lease_expires_at = None
            job.error = "execution lease expired; manual review required before retry"
            stalled += 1
            _audit_pending(
                db,
                "system",
                "job.execution.stalled",
                "job",
                job.id,
                {"attempt_count": job.attempt_count, "action": job.action},
            )

    if expired:
        db.commit()
    return {"requeued": requeued, "stalled": stalled}


def _terminal_result_matches(job: PatchJob, body: JobResultRequest) -> bool:
    return (
        job.status == body.status
        and job.result_json == dump(body.result)
        and job.error == body.error
    )


@app.post("/api/auth/login")
def login(body: LoginRequest, db: Session = Depends(get_db)):
    try:
        username = validate_username(body.username)
    except ValueError:
        raise HTTPException(status_code=401, detail="invalid credentials")

    user = db.query(AdminUser).filter(AdminUser.username == username).first()
    if not user or not user.active or not password_verify(user.password_hash, body.password):
        raise HTTPException(status_code=401, detail="invalid credentials")

    if password_needs_rehash(user.password_hash):
        user.password_hash = password_hash(body.password)

    raw_token, session = create_session(db, user)
    audit(
        db,
        f"user:{user.username}",
        "auth.login",
        "session",
        session.id,
        {"role": user.role},
    )
    return {
        "session_token": raw_token,
        "expires_at": session.expires_at.isoformat(),
        "user": serialize_admin_user(user),
    }


@app.post("/api/auth/logout")
def logout(
    x_session_token: str | None = Header(default=None),
    principal=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    actor = principal["actor"]
    revoked = revoke_session(db, x_session_token or "")
    audit(db, actor, "auth.logout", "session", principal.get("session_id", ""), {"revoked": revoked})
    return {"ok": True}


@app.get("/api/auth/me")
def auth_me(principal=Depends(require_viewer), db: Session = Depends(get_db)):
    if principal.get("kind") == "break_glass":
        return {
            "id": "",
            "username": "break-glass",
            "role": "admin",
            "active": True,
            "break_glass": True,
        }
    user = db.get(AdminUser, principal["user_id"])
    if not user:
        raise HTTPException(status_code=401, detail="user not found")
    return {**serialize_admin_user(user), "break_glass": False}


@app.post("/api/auth/change-password")
def change_password(
    body: PasswordChangeRequest,
    principal=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    if principal.get("kind") != "user":
        raise HTTPException(status_code=409, detail="break-glass principal has no password")

    user = db.get(AdminUser, principal["user_id"])
    if not user or not password_verify(user.password_hash, body.current_password):
        raise HTTPException(status_code=401, detail="current password is invalid")

    try:
        validate_password_strength(body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    user.password_hash = password_hash(body.new_password)
    sessions = db.query(AdminSession).filter(
        AdminSession.user_id == user.id,
        AdminSession.id != principal["session_id"],
    ).all()
    for session in sessions:
        db.delete(session)
    db.commit()
    audit(
        db,
        principal["actor"],
        "auth.password.changed",
        "user",
        user.id,
        {"other_sessions_revoked": len(sessions)},
    )
    return {"ok": True, "other_sessions_revoked": len(sessions)}


@app.get("/api/admin/users")
def list_users(_=Depends(require_admin), db: Session = Depends(get_db)):
    return [serialize_admin_user(user) for user in db.query(AdminUser).order_by(AdminUser.username.asc()).all()]


@app.post("/api/admin/users")
def create_user(
    body: UserCreateRequest,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        username = validate_username(body.username)
        role = validate_role(body.role)
        validate_password_strength(body.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if db.query(AdminUser).filter(AdminUser.username == username).first():
        raise HTTPException(status_code=409, detail="username already exists")

    user = AdminUser(
        id=str(uuid.uuid4()),
        username=username,
        password_hash=password_hash(body.password),
        role=role,
        active=True,
    )
    db.add(user)
    db.commit()
    audit(
        db,
        principal["actor"],
        "auth.user.created",
        "user",
        user.id,
        {"username": user.username, "role": user.role},
    )
    return serialize_admin_user(user)


@app.patch("/api/admin/users/{user_id}")
def update_user(
    user_id: str,
    body: UserUpdateRequest,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.get(AdminUser, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user not found")

    requested_role = user.role
    if body.role is not None:
        try:
            requested_role = validate_role(body.role)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    requested_active = user.active if body.active is None else body.active

    if user.id == principal.get("user_id"):
        if requested_role != user.role:
            raise HTTPException(status_code=409, detail="cannot change the current user's own role")
        if requested_active is False:
            raise HTTPException(status_code=409, detail="cannot deactivate the current user")

    removing_active_admin = (
        user.role == "admin"
        and user.active
        and (requested_role != "admin" or requested_active is False)
    )
    if removing_active_admin:
        active_admins = db.query(AdminUser).filter(
            AdminUser.role == "admin",
            AdminUser.active.is_(True),
        ).count()
        if active_admins <= 1:
            raise HTTPException(status_code=409, detail="cannot remove or deactivate the last active admin")

    user.role = requested_role
    user.active = requested_active
    if not user.active:
        sessions = db.query(AdminSession).filter(AdminSession.user_id == user.id).all()
        for session in sessions:
            db.delete(session)

    db.commit()
    audit(
        db,
        principal["actor"],
        "auth.user.updated",
        "user",
        user.id,
        {"username": user.username, "role": user.role, "active": user.active},
    )
    return serialize_admin_user(user)


@app.get("/")
def root():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health():
    return {"status": "ok", "version": "0.17.0", "time": now().isoformat()}


@app.get("/ready")
def ready():
    return readiness_response()


@app.get("/metrics", include_in_schema=False)
def metrics():
    return metrics_response()


@app.post("/api/agent/register", response_model=RegisterResponse)
def register_agent(
    body: RegisterRequest,
    _=Depends(require_enrollment),
    x_client_cert_fingerprint: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    fingerprint = require_agent_mtls_fingerprint(x_client_cert_fingerprint)

    if fingerprint:
        existing = db.query(Agent).filter(Agent.client_cert_fingerprint == fingerprint).first()
        if existing:
            raise HTTPException(status_code=409, detail="client certificate is already bound to an agent")

    agent_id = str(uuid.uuid4())
    raw_token = new_token()
    agent = Agent(
        id=agent_id,
        hostname=body.hostname,
        os_family=body.os_family.lower(),
        os_name=body.os_name,
        os_version=body.os_version,
        arch=body.arch,
        ip_address=body.ip_address,
        tags=dump(body.tags),
        token_hash=hash_token(raw_token),
        client_cert_fingerprint=fingerprint or None,
        last_seen=now(),
    )
    db.add(agent)
    db.commit()
    audit(
        db,
        f"agent:{agent_id}",
        "agent.registered",
        "agent",
        agent_id,
        {
            "hostname": body.hostname,
            "mtls_bound": bool(fingerprint),
            "client_cert_fingerprint": fingerprint,
        },
    )
    return RegisterResponse(agent_id=agent_id, agent_token=raw_token)


def signed_agent_release():
    if not AGENT_UPDATE_ENABLED:
        raise AgentReleaseError("agent update distribution is disabled")
    return load_signed_release(
        AGENT_RELEASE_DIR,
        AGENT_UPDATE_PUBLIC_KEY_FILE,
    )


def signed_release_binding(expected_version: str) -> dict:
    try:
        release = signed_agent_release()
    except AgentReleaseError as exc:
        raise HTTPException(
            status_code=409,
            detail=f"signed agent release is unavailable: {str(exc)[:300]}",
        ) from exc

    manifest = release["manifest"]
    if manifest["version"] != expected_version:
        raise HTTPException(
            status_code=409,
            detail=(
                "approved version does not match the currently published signed release "
                f"(published={manifest['version']})"
            ),
        )

    return {
        "version": manifest["version"],
        "artifact_sha256": manifest["artifact"]["sha256"],
        "source_commit": manifest["source_commit"],
        "signing_key_id": manifest["signing_key_id"],
    }


def staged_release_binding_matches(agent: Agent, binding: dict) -> tuple[bool, str]:
    inventory = load(agent.inventory_json, {})
    update_state = inventory.get("update") if isinstance(inventory.get("update"), dict) else {}

    if update_state.get("status") != "staged":
        return False, "not_staged"
    if str(update_state.get("staged_version") or "") != str(binding.get("version") or ""):
        return False, "staged_version_mismatch"
    if str(update_state.get("artifact_sha256") or "").lower() != str(binding.get("artifact_sha256") or "").lower():
        return False, "artifact_sha256_mismatch"
    if str(update_state.get("source_commit") or "").lower() != str(binding.get("source_commit") or "").lower():
        return False, "source_commit_mismatch"
    if str(update_state.get("signing_key_id") or "").lower() != str(binding.get("signing_key_id") or "").lower():
        return False, "signing_key_id_mismatch"
    return True, "binding_match"


@app.get("/api/agent/{agent_id}/updates/latest")
def agent_update_latest(
    agent_id: str,
    x_agent_token: str | None = Header(default=None),
    x_client_cert_fingerprint: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    agent = get_agent(db, agent_id, x_agent_token, x_client_cert_fingerprint)
    runtime = agent_runtime_metadata(agent)

    if not AGENT_UPDATE_ENABLED:
        return {
            "enabled": False,
            "available": False,
            "status": "disabled",
            "current_version": runtime.get("version", ""),
        }

    try:
        release = signed_agent_release()
    except AgentReleaseError as exc:
        return {
            "enabled": True,
            "available": False,
            "status": "unavailable",
            "current_version": runtime.get("version", ""),
            "error": str(exc)[:500],
        }

    manifest = release["manifest"]
    current_version = runtime.get("version", "")
    available = bool(
        current_version
        and manifest["version"] != current_version
        and version_at_least(manifest["version"], current_version)
    )

    response = {
        "enabled": True,
        "available": available,
        "status": "available" if available else "current",
        "current_version": current_version,
        "latest_version": manifest["version"],
    }
    if available:
        response.update({
            "manifest": manifest,
            "signature": base64.b64encode(release["signature"]).decode("ascii"),
            "artifact_url": (
                f"/api/agent/{agent.id}/updates/artifact/"
                f"{manifest['artifact']['filename']}"
            ),
        })
    return response


@app.get("/api/agent/{agent_id}/updates/artifact/{filename}")
def agent_update_artifact(
    agent_id: str,
    filename: str,
    x_agent_token: str | None = Header(default=None),
    x_client_cert_fingerprint: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    get_agent(db, agent_id, x_agent_token, x_client_cert_fingerprint)

    try:
        release = signed_agent_release()
    except AgentReleaseError:
        raise HTTPException(status_code=404, detail="signed agent release unavailable")

    expected = release["manifest"]["artifact"]["filename"]
    if filename != expected:
        raise HTTPException(status_code=404, detail="agent release artifact not found")

    return FileResponse(
        path=release["artifact_path"],
        filename=expected,
        media_type="application/zip",
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.post("/api/agent/{agent_id}/heartbeat")
def heartbeat(
    agent_id: str,
    body: HeartbeatRequest,
    x_agent_token: str | None = Header(default=None),
    x_client_cert_fingerprint: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    agent = get_agent(db, agent_id, x_agent_token, x_client_cert_fingerprint)
    previous_inventory = load(agent.inventory_json, {})
    previous_activation = (
        previous_inventory.get("activation")
        if isinstance(previous_inventory.get("activation"), dict)
        else {}
    )
    current_activation = (
        body.inventory.get("activation")
        if isinstance(body.inventory.get("activation"), dict)
        else {}
    )
    previous_activation_status = str(previous_activation.get("status") or "")
    current_activation_status = str(current_activation.get("status") or "")

    if (
        current_activation_status
        and current_activation_status != previous_activation_status
        and current_activation_status in {
            "committed",
            "rolled_back",
            "aborted_before_switch",
            "error",
        }
    ):
        _audit_pending(
            db,
            f"agent:{agent.id}",
            "agent.update.activation." + current_activation_status,
            "agent",
            agent.id,
            {
                "previous_status": previous_activation_status,
                "status": current_activation_status,
                "previous_version": current_activation.get("previous_version", ""),
                "target_version": current_activation.get("target_version", ""),
                "confirmed_version": current_activation.get("confirmed_version", ""),
                "attempts": current_activation.get("attempts", 0),
                "rollback_reason": current_activation.get("rollback_reason", ""),
                "last_error": str(current_activation.get("last_error") or "")[:500],
            },
        )

    agent.last_seen = now()
    agent.inventory_json = dump(body.inventory)
    agent.patch_scan_json = dump(body.patch_scan)
    agent.reboot_required = body.reboot_required
    agent.pending_updates = len(body.patch_scan)
    agent.critical_updates = sum(1 for x in body.patch_scan if str(x.get("severity", "")).lower() in {"critical", "important", "security"})
    catalog_sync = sync_patch_catalog_for_agent(db, agent, body.patch_scan)
    db.commit()
    unblocked = reconcile_blocked_agent_jobs(db, agent)
    return {
        "ok": True,
        "agent_compatibility": agent_runtime_metadata(agent),
        "jobs_unblocked": unblocked,
        "patch_catalog": catalog_sync,
    }


@app.get("/api/agent/{agent_id}/jobs")
def poll_jobs(
    agent_id: str,
    x_agent_token: str | None = Header(default=None),
    x_client_cert_fingerprint: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    agent = get_agent(db, agent_id, x_agent_token, x_client_cert_fingerprint)
    sweep_expired_job_leases(db, agent.id)
    t = now()

    jobs = db.query(PatchJob).filter(
        PatchJob.agent_id == agent.id,
        PatchJob.status == "pending",
    ).order_by(PatchJob.created_at.asc()).limit(100).all()

    blocked_any = False
    for job in jobs:
        authorized, authorization_reason = agent_update_authorization_check(job, agent, t)
        if not authorized:
            invalidate_agent_update_authorization(db, job, authorization_reason)
            continue

        if block_incompatible_job(db, job, agent):
            blocked_any = True
            continue

        if job.not_before:
            nb = job.not_before
            if nb.tzinfo is None:
                nb = nb.replace(tzinfo=timezone.utc)
            if nb > t:
                continue

        payload = load(job.payload_json, {})
        if not maintenance_window_state(payload, t)["eligible_now"]:
            continue

        claim_token = new_token()
        lease_expires = t + timedelta(seconds=JOB_CLAIM_LEASE_SECONDS)
        updated = db.query(PatchJob).filter(
            PatchJob.id == job.id,
            PatchJob.status == "pending",
        ).update(
            {
                PatchJob.status: "claimed",
                PatchJob.claimed_at: t,
                PatchJob.claim_token_hash: hash_token(claim_token),
                PatchJob.lease_expires_at: lease_expires,
                PatchJob.last_lease_at: t,
                PatchJob.attempt_count: PatchJob.attempt_count + 1,
            },
            synchronize_session=False,
        )
        if updated != 1:
            db.rollback()
            continue

        _audit_pending(
            db,
            f"agent:{agent.id}",
            "job.claimed",
            "job",
            job.id,
            {"lease_seconds": JOB_CLAIM_LEASE_SECONDS},
        )
        db.commit()
        db.expire_all()
        claimed = db.get(PatchJob, job.id)
        return [serialize_job(claimed, claim_token=claim_token)]

    if blocked_any:
        db.commit()

    return []


@app.post("/api/agent/{agent_id}/jobs/{job_id}/lease")
def renew_job_lease(
    agent_id: str,
    job_id: str,
    body: LeaseRenewRequest,
    x_agent_token: str | None = Header(default=None),
    x_client_cert_fingerprint: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    agent = get_agent(db, agent_id, x_agent_token, x_client_cert_fingerprint)
    job = db.get(PatchJob, job_id)
    if not job or job.agent_id != agent.id:
        raise HTTPException(status_code=404, detail="job not found")
    if job.status not in {"claimed", "running"}:
        raise HTTPException(status_code=409, detail="job lease cannot be renewed in current state")
    if not _job_claim_matches(job, body.claim_token):
        raise HTTPException(status_code=409, detail="stale or invalid job claim")

    lease_seconds = JOB_RUNNING_LEASE_SECONDS if job.status == "running" else JOB_CLAIM_LEASE_SECONDS
    t = now()
    job.last_lease_at = t
    job.lease_expires_at = t + timedelta(seconds=lease_seconds)
    db.commit()
    return {
        "ok": True,
        "status": job.status,
        "lease_seconds": lease_seconds,
        "lease_expires_at": job.lease_expires_at.isoformat(),
    }


@app.post("/api/agent/{agent_id}/jobs/{job_id}/result")
def job_result(
    agent_id: str,
    job_id: str,
    body: JobResultRequest,
    x_agent_token: str | None = Header(default=None),
    x_client_cert_fingerprint: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    agent = get_agent(db, agent_id, x_agent_token, x_client_cert_fingerprint)
    job = db.get(PatchJob, job_id)
    if not job or job.agent_id != agent.id:
        raise HTTPException(status_code=404, detail="job not found")
    if body.status not in {"running", "success", "failed", "skipped"}:
        raise HTTPException(status_code=400, detail="invalid status")
    if not _job_claim_matches(job, body.claim_token):
        raise HTTPException(status_code=409, detail="stale or invalid job claim")

    if job.status in TERMINAL_JOB_STATUSES:
        if _terminal_result_matches(job, body):
            return {"ok": True, "idempotent": True}
        raise HTTPException(status_code=409, detail="job is already terminal with a different result")

    if job.status == "stalled" and body.status == "running":
        raise HTTPException(status_code=409, detail="stalled job requires manual review before retry")
    if job.status not in {"claimed", "running", "stalled"}:
        raise HTTPException(status_code=409, detail="job is not owned by an active execution attempt")

    previous_status = job.status
    job.status = body.status
    job.result_json = dump(body.result)
    job.error = body.error

    if body.started_at:
        job.started_at = body.started_at
    elif body.status == "running" and not job.started_at:
        job.started_at = now()

    if body.status == "running":
        t = now()
        job.last_lease_at = t
        job.lease_expires_at = t + timedelta(seconds=JOB_RUNNING_LEASE_SECONDS)
    else:
        if body.finished_at:
            job.finished_at = body.finished_at
        else:
            job.finished_at = now()
        job.lease_expires_at = None

    db.commit()
    audit(
        db,
        f"agent:{agent.id}",
        f"job.{body.status}",
        "job",
        job.id,
        {
            "campaign_id": job.campaign_id,
            "error": body.error,
            "previous_status": previous_status,
            "attempt_count": job.attempt_count,
        },
    )
    return {"ok": True, "idempotent": False}


@app.get("/api/admin/agent-release")
def admin_agent_release(_=Depends(require_viewer)):
    if not AGENT_UPDATE_ENABLED:
        return {
            "enabled": False,
            "ready": False,
            "status": "disabled",
        }

    try:
        release = signed_agent_release()
    except AgentReleaseError as exc:
        return {
            "enabled": True,
            "ready": False,
            "status": "unavailable",
            "error": str(exc)[:500],
        }

    manifest = release["manifest"]
    return {
        "enabled": True,
        "ready": True,
        "status": "ready",
        "version": manifest["version"],
        "protocol": manifest["protocol"],
        "capabilities": manifest["capabilities"],
        "generated_at": manifest["generated_at"],
        "source_commit": manifest["source_commit"],
        "signing_key_id": manifest["signing_key_id"],
        "artifact": {
            "filename": manifest["artifact"]["filename"],
            "sha256": manifest["artifact"]["sha256"],
            "size_bytes": manifest["artifact"]["size_bytes"],
        },
    }


@app.get("/api/admin/summary")
def admin_summary(_=Depends(require_viewer), db: Session = Depends(get_db)):
    sweep_expired_job_leases(db)
    agents = db.query(Agent).all()
    total = len(agents)
    
    def is_online(a):
        if not a.last_seen:
            return False
        ls = a.last_seen
        if ls.tzinfo is None:
            ls = ls.replace(tzinfo=timezone.utc)
        return (now() - ls).total_seconds() < 900
    online = sum(1 for a in agents if is_online(a))
    compliant = sum(1 for a in agents if a.pending_updates == 0)
    sla_report = vulnerability_sla_report(db)
    remediation_report = remediation_queue_report(db)
    asset_report = asset_risk_report(db)
    return {
        "agents": total,
        "online": online,
        "compliant": compliant,
        "compliance_percent": round((compliant / total * 100), 1) if total else 0,
        "pending_updates": sum(a.pending_updates for a in agents),
        "critical_updates": sum(a.critical_updates for a in agents),
        "reboot_required": sum(1 for a in agents if a.reboot_required),
        "failed_jobs": db.query(PatchJob).filter(PatchJob.status == "failed").count(),
        "open_vulnerabilities": db.query(VulnerabilityFinding).filter(VulnerabilityFinding.status == "open").count(),
        "critical_vulnerabilities": db.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.status == "open",
            VulnerabilityFinding.severity == "critical",
        ).count(),
        "unmatched_vulnerabilities": db.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.status == "open",
            VulnerabilityFinding.agent_id.is_(None),
        ).count(),
        "sla_breached_vulnerabilities": sla_report["summary"]["breached"],
        "sla_due_soon_vulnerabilities": sla_report["summary"]["due_soon"],
        "sla_exception_vulnerabilities": sla_report["summary"]["exception"],
        "urgent_risk_vulnerabilities": sum(
            1
            for finding in db.query(VulnerabilityFinding).filter(VulnerabilityFinding.status == "open").all()
            if vulnerability_risk(finding)["level"] == "urgent"
        ),
        "remediation_ready_vulnerabilities": remediation_report["summary"]["eligible_for_campaign"],
        "critical_risk_assets": asset_report["summary"]["critical"],
        "high_risk_assets": asset_report["summary"]["high"],
        "average_asset_risk": asset_report["summary"]["average_score"],
        "assets_above_risk_appetite": asset_report["summary"]["above_risk_appetite"],
        "assets_risk_accepted": asset_report["summary"]["accepted_above_appetite"],
        "assets_risk_in_treatment": asset_report["summary"]["in_treatment_above_appetite"],
        "assets_risk_treatment_overdue": asset_report["summary"]["overdue_treatment_above_appetite"],
        "assets_risk_untreated": asset_report["summary"]["untreated_above_appetite"],
        "asset_risk_appetite": asset_report["summary"]["risk_appetite"],
        "agent_supported": sum(1 for a in agents if agent_runtime_metadata(a)["status"] == "supported"),
        "agent_outdated": sum(1 for a in agents if agent_runtime_metadata(a)["status"] == "outdated"),
        "agent_unknown": sum(1 for a in agents if agent_runtime_metadata(a)["status"] == "unknown"),
        "agent_protocol_unsupported": sum(
            1 for a in agents if agent_runtime_metadata(a)["status"] == "protocol_unsupported"
        ),
        "compatibility_enforced": AGENT_ENFORCE_COMPATIBILITY,
        "minimum_agent_version": AGENT_MIN_VERSION,
        "minimum_agent_protocol": AGENT_MIN_PROTOCOL,
        "blocked_jobs": db.query(PatchJob).filter(PatchJob.status == "blocked").count(),
        "agent_update_staged": sum(
            1 for a in agents
            if (load(a.inventory_json, {}).get("update") or {}).get("status") == "staged"
        ),
        "agent_update_errors": sum(
            1 for a in agents
            if (load(a.inventory_json, {}).get("update") or {}).get("status") == "error"
        ),
        "agent_update_distribution_enabled": AGENT_UPDATE_ENABLED,
        "agent_activation_pending": sum(
            1 for a in agents
            if (load(a.inventory_json, {}).get("activation") or {}).get("status") in {"switching", "pending"}
        ),
        "agent_activation_rollbacks": sum(
            1 for a in agents
            if (load(a.inventory_json, {}).get("activation") or {}).get("status") == "rolled_back"
        ),
        "agent_update_quarantined": sum(
            1 for a in agents
            if (load(a.inventory_json, {}).get("update") or {}).get("status") == "quarantined"
        ),
        "agent_update_approvals_pending": db.query(PatchJob).filter(
            PatchJob.action == "activate_agent_update",
            PatchJob.status == "pending",
        ).count(),
        "agent_update_approvals_expired": sum(
            1
            for job in db.query(PatchJob).filter(
                PatchJob.action == "activate_agent_update",
                PatchJob.status == "pending",
            ).all()
            if (
                _approval_expiry(load(job.payload_json, {})) is None
                or _approval_expiry(load(job.payload_json, {})) <= now()
            )
        ),
    }


@app.post("/api/admin/reports/asset-risk/snapshot")
def snapshot_asset_risk(
    principal=Depends(require_operator),
    db: Session = Depends(get_db),
):
    result = capture_asset_risk_snapshots(db, source=f"manual:{principal['actor']}", minimum_interval_seconds=0)
    audit(
        db,
        principal["actor"],
        "asset_risk.snapshot.created",
        "asset_risk",
        "",
        result,
    )
    return {"ok": True, "result": result}


@app.get("/api/admin/reports/asset-risk/history")
def admin_asset_risk_history(
    agent_id: str | None = None,
    limit: int = 500,
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    return asset_risk_history(db, agent_id=agent_id, limit=limit)


@app.get("/api/admin/reports/asset-risk")
def admin_asset_risk_report(
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    return asset_risk_report(db)


@app.get("/api/admin/agents/{agent_id}/risk-reduction-plan")
def risk_reduction_plan(
    agent_id: str,
    max_steps: int = 25,
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    return risk_reduction_plan_report(db, agent_id=agent_id, max_steps=max_steps)


@app.get("/api/admin/risk-goals")
def list_risk_reduction_goals(
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    return risk_reduction_goals_report(db)


@app.post("/api/admin/risk-goals")
def create_risk_reduction_goal(
    body: RiskReductionGoalCreate,
    principal=Depends(require_operator),
    db: Session = Depends(get_db),
):
    name = body.name.strip()
    owner = body.owner.strip()
    scope_tag = body.scope_tag.strip().lower()
    reason = body.reason.strip()
    goal_type = body.goal_type.strip().lower()
    if len(name) < 3:
        raise HTTPException(status_code=400, detail="goal name must contain at least 3 non-space characters")
    if len(owner) < 2:
        raise HTTPException(status_code=400, detail="goal owner must contain at least 2 non-space characters")
    if len(reason) < 5:
        raise HTTPException(status_code=400, detail="goal reason must contain at least 5 non-space characters")
    if goal_type not in RISK_REDUCTION_GOAL_TYPES:
        raise HTTPException(status_code=400, detail="unsupported risk reduction goal type")
    if db.query(RiskReductionGoal).filter(RiskReductionGoal.name == name).first():
        raise HTTPException(status_code=409, detail="risk reduction goal name already exists")

    due_at = body.due_at
    if due_at.tzinfo is None:
        due_at = due_at.replace(tzinfo=timezone.utc)
    current = now()
    if due_at <= current:
        raise HTTPException(status_code=400, detail="goal due date must be in the future")
    if due_at > current + timedelta(days=1095):
        raise HTTPException(status_code=400, detail="goal due date cannot exceed 3 years")

    baseline, scoped_assets = _goal_metric_value(db, goal_type, scope_tag, current)
    if scoped_assets < 1:
        raise HTTPException(status_code=409, detail="goal scope does not contain managed assets")
    if baseline <= float(body.target_value):
        raise HTTPException(
            status_code=409,
            detail={
                "message": "goal target must be lower than the current baseline",
                "baseline_value": baseline,
                "target_value": body.target_value,
            },
        )

    goal = RiskReductionGoal(
        id=str(uuid.uuid4()),
        name=name,
        scope_tag=scope_tag,
        goal_type=goal_type,
        target_value=float(body.target_value),
        baseline_value=baseline,
        owner=owner,
        due_at=due_at,
        status="active",
        reason=reason,
        created_by=principal["actor"],
        updated_by=principal["actor"],
    )
    db.add(goal)
    db.commit()
    db.refresh(goal)
    result = serialize_risk_reduction_goal(db, goal, current)
    audit(
        db,
        principal["actor"],
        "risk_reduction.goal.created",
        "risk_reduction_goal",
        goal.id,
        result,
    )
    return {"ok": True, "goal": result}


@app.put("/api/admin/risk-goals/{goal_id}")
def update_risk_reduction_goal(
    goal_id: str,
    body: RiskReductionGoalUpdate,
    principal=Depends(require_operator),
    db: Session = Depends(get_db),
):
    goal = db.query(RiskReductionGoal).filter(
        RiskReductionGoal.id == goal_id
    ).with_for_update().first()
    if not goal:
        raise HTTPException(status_code=404, detail="risk reduction goal not found")

    before = serialize_risk_reduction_goal(db, goal)
    reason = body.reason.strip()
    if len(reason) < 5:
        raise HTTPException(status_code=400, detail="goal reason must contain at least 5 non-space characters")
    if body.owner is not None:
        owner = body.owner.strip()
        if len(owner) < 2:
            raise HTTPException(status_code=400, detail="goal owner must contain at least 2 non-space characters")
        goal.owner = owner
    if body.target_value is not None:
        if float(body.target_value) >= float(goal.baseline_value):
            raise HTTPException(status_code=409, detail="goal target must remain below its baseline")
        goal.target_value = float(body.target_value)
    if body.due_at is not None:
        due_at = body.due_at
        if due_at.tzinfo is None:
            due_at = due_at.replace(tzinfo=timezone.utc)
        if due_at <= now() and (body.status or goal.status) == "active":
            raise HTTPException(status_code=400, detail="active goal due date must be in the future")
        goal.due_at = due_at
    if body.status is not None:
        status = body.status.strip().lower()
        if status not in {"active", "completed", "cancelled"}:
            raise HTTPException(status_code=400, detail="unsupported goal status")
        if status == "completed":
            current_value, _ = _goal_metric_value(db, goal.goal_type, goal.scope_tag)
            if current_value > float(goal.target_value):
                raise HTTPException(status_code=409, detail="goal cannot be completed before the target is achieved")
            goal.completed_at = now()
        elif status == "active":
            if goal.due_at <= now():
                raise HTTPException(status_code=409, detail="expired goal cannot be reactivated without a future due date")
            goal.completed_at = None
        else:
            goal.completed_at = None
        goal.status = status

    goal.reason = reason
    goal.updated_by = principal["actor"]
    goal.updated_at = now()
    db.commit()
    db.refresh(goal)
    after = serialize_risk_reduction_goal(db, goal)
    audit(
        db,
        principal["actor"],
        "risk_reduction.goal.updated",
        "risk_reduction_goal",
        goal.id,
        {"before": before, "after": after},
    )
    return {"ok": True, "goal": after}


@app.get("/api/admin/reports/business-context")
def business_context(
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    return business_context_report(db)


@app.get("/api/admin/reports/remediation-performance")
def remediation_performance(
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    return remediation_performance_report(db)


@app.get("/api/admin/reports/active-threat-watch")
def active_threat_watch(
    limit: int = 50,
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    return active_threat_watch_report(db, limit=limit)







@app.get("/api/admin/freeze-windows")
def list_freeze_windows(
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    reference = now()
    items = db.query(PatchFreezeWindow).order_by(PatchFreezeWindow.starts_at.asc()).all()
    return {
        "generated_at": reference.isoformat(),
        "summary": {
            "windows": len(items),
            "active": sum(1 for item in items if serialize_freeze_window(item, reference)["active"]),
            "enabled": sum(1 for item in items if item.enabled),
        },
        "items": [serialize_freeze_window(item, reference) for item in items],
    }


@app.post("/api/admin/freeze-windows")
def create_freeze_window(
    body: PatchFreezeWindowCreate,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    starts_at = body.starts_at if body.starts_at.tzinfo else body.starts_at.replace(tzinfo=timezone.utc)
    ends_at = body.ends_at if body.ends_at.tzinfo else body.ends_at.replace(tzinfo=timezone.utc)
    if ends_at <= starts_at:
        raise HTTPException(status_code=400, detail="freeze window end must be after start")
    if db.query(PatchFreezeWindow).filter(func.lower(PatchFreezeWindow.name) == body.name.strip().lower()).first():
        raise HTTPException(status_code=409, detail="freeze window name already exists")
    item = PatchFreezeWindow(
        id=str(uuid.uuid4()),
        name=body.name.strip(),
        target_os=body.target_os.strip().lower() or "all",
        target_tag=body.target_tag.strip(),
        starts_at=starts_at,
        ends_at=ends_at,
        enabled=True,
        reason=body.reason.strip(),
        created_by=principal["actor"],
        updated_by=principal["actor"],
    )
    db.add(item)
    db.commit()
    audit(db, principal["actor"], "patch_freeze.created", "patch_freeze", item.id, serialize_freeze_window(item))
    return serialize_freeze_window(item)


@app.patch("/api/admin/freeze-windows/{window_id}")
def update_freeze_window(
    window_id: str,
    body: PatchFreezeWindowUpdate,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    item = db.get(PatchFreezeWindow, window_id)
    if not item:
        raise HTTPException(status_code=404, detail="freeze window not found")
    item.enabled = body.enabled
    item.updated_by = principal["actor"]
    db.commit()
    audit(db, principal["actor"], "patch_freeze.updated", "patch_freeze", item.id, {
        "enabled": body.enabled,
        "reason": body.reason.strip(),
    })
    return serialize_freeze_window(item)


@app.post("/api/admin/campaigns/{campaign_id}/freeze-override")
def approve_campaign_freeze_override(
    campaign_id: str,
    body: CampaignFreezeOverrideCreate,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    campaign = db.get(Campaign, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="campaign not found")
    windows = active_freeze_windows_for_campaign(db, campaign)
    if not windows:
        raise HTTPException(status_code=409, detail="campaign is not currently blocked by a freeze window")
    existing = active_campaign_freeze_override(db, campaign.id)
    if existing:
        return {"ok": True, "override_id": existing.id, "already_active": True}
    item = CampaignFreezeOverride(
        id=str(uuid.uuid4()),
        campaign_id=campaign.id,
        reason=body.reason.strip(),
        approved_by=principal["actor"],
        approved_at=now(),
    )
    db.add(item)
    db.commit()
    audit(db, principal["actor"], "campaign.freeze_override.approved", "campaign", campaign.id, {
        "override_id": item.id,
        "reason": item.reason,
        "freeze_window_ids": [window.id for window in windows],
    })
    return {"ok": True, "override_id": item.id}


@app.post("/api/admin/campaigns/{campaign_id}/freeze-override/revoke")
def revoke_campaign_freeze_override(
    campaign_id: str,
    body: CampaignFreezeOverrideRevoke,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    item = active_campaign_freeze_override(db, campaign_id)
    if not item:
        raise HTTPException(status_code=404, detail="active freeze override not found")
    item.revoked_by = principal["actor"]
    item.revoked_at = now()
    item.revoke_reason = body.reason.strip()
    db.commit()
    audit(db, principal["actor"], "campaign.freeze_override.revoked", "campaign", campaign_id, {
        "override_id": item.id,
        "reason": item.revoke_reason,
    })
    return {"ok": True}


@app.get("/api/admin/patch-feeds")
def list_patch_feeds(
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    return patch_feed_orchestrator_report(db)


@app.post("/api/admin/patch-feeds")
def create_patch_feed(
    body: PatchFeedProviderCreate,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    provider_type = body.provider_type.strip().lower()
    if provider_type not in {"curated", "msrc_cvrf", "ubuntu_security"}:
        raise HTTPException(status_code=400, detail="unsupported patch feed provider type")
    if db.query(PatchFeedProvider).filter(func.lower(PatchFeedProvider.name) == body.name.strip().lower()).first():
        raise HTTPException(status_code=409, detail="patch feed provider name already exists")
    provider = PatchFeedProvider(
        id=str(uuid.uuid4()),
        name=body.name.strip(),
        provider_type=provider_type,
        enabled=body.enabled,
        priority=body.priority,
        ttl_hours=body.ttl_hours,
        interval_seconds=body.interval_seconds,
        failure_threshold=body.failure_threshold,
        cooldown_seconds=body.cooldown_seconds,
        records_json=dump([item.model_dump(mode="json", exclude_none=True) for item in body.records]),
        provider_config_json=dump(body.config or {}),
        adapter_state_json="{}",
        created_by=principal["actor"],
        updated_by=principal["actor"],
    )
    db.add(provider)
    db.commit()
    audit(db, principal["actor"], "patch_feed.created", "patch_feed", provider.id, {
        "name": provider.name,
        "provider_type": provider.provider_type,
        "record_count": len(body.records),
    })
    PATCH_FEED_WAKE.set()
    return serialize_patch_feed_provider(provider)


@app.patch("/api/admin/patch-feeds/{provider_id}")
def update_patch_feed(
    provider_id: str,
    body: PatchFeedProviderUpdate,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    provider = db.get(PatchFeedProvider, provider_id)
    if not provider:
        raise HTTPException(status_code=404, detail="patch feed provider not found")
    before = serialize_patch_feed_provider(provider)
    for field in ("enabled", "priority", "ttl_hours", "interval_seconds", "failure_threshold", "cooldown_seconds"):
        value = getattr(body, field)
        if value is not None:
            setattr(provider, field, value)
    if body.records is not None:
        provider.records_json = dump([item.model_dump(mode="json", exclude_none=True) for item in body.records])
    if body.config is not None:
        provider.provider_config_json = dump(body.config)
        provider.adapter_state_json = "{}"
    provider.updated_by = principal["actor"]
    db.commit()
    after = serialize_patch_feed_provider(provider)
    audit(db, principal["actor"], "patch_feed.updated", "patch_feed", provider.id, {
        "before": before,
        "after": after,
    })
    PATCH_FEED_WAKE.set()
    return after


@app.post("/api/admin/patch-feeds/{provider_id}/sync")
def sync_patch_feed(
    provider_id: str,
    principal=Depends(require_operator),
    db: Session = Depends(get_db),
):
    provider = db.get(PatchFeedProvider, provider_id)
    if not provider:
        raise HTTPException(status_code=404, detail="patch feed provider not found")
    try:
        with PATCH_FEED_SYNC_LOCK:
            result = run_patch_feed_provider(db, provider, principal["actor"])
        audit(db, principal["actor"], "patch_feed.sync", "patch_feed", provider.id, result)
        return result
    except RuntimeError as exc:
        audit(db, principal["actor"], "patch_feed.sync.failed", "patch_feed", provider.id, {
            "error": str(exc)[:500],
        })
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/admin/patch-feeds/{provider_id}/circuit/reset")
def reset_patch_feed_circuit(
    provider_id: str,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    provider = db.get(PatchFeedProvider, provider_id)
    if not provider:
        raise HTTPException(status_code=404, detail="patch feed provider not found")
    provider.consecutive_failures = 0
    provider.circuit_open_until = None
    provider.last_error = ""
    provider.updated_by = principal["actor"]
    db.commit()
    audit(db, principal["actor"], "patch_feed.circuit.reset", "patch_feed", provider.id, {})
    PATCH_FEED_WAKE.set()
    return serialize_patch_feed_provider(provider)


@app.post("/api/admin/patch-catalog/metadata/import")
def import_patch_catalog_metadata(
    body: PatchMetadataImportRequest,
    principal=Depends(require_operator),
    db: Session = Depends(get_db),
):
    result = import_patch_metadata(db, body, principal["actor"])
    audit(
        db,
        principal["actor"],
        "patch_catalog.metadata.imported",
        "patch_catalog",
        body.source.strip().lower(),
        {
            "priority": body.priority,
            "dry_run": body.dry_run,
            "summary": result["summary"],
        },
    )
    return result


@app.patch("/api/admin/patch-catalog/{patch_ref}/lifecycle")
def update_patch_catalog_lifecycle(
    patch_ref: str,
    body: PatchCatalogLifecycleUpdate,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    key = patch_ref_key(patch_ref)
    entry = db.get(PatchCatalogEntry, key)
    if not entry:
        raise HTTPException(status_code=404, detail="patch catalog entry not found")

    supersedes = []
    for value in body.supersedes:
        ref = normalize_patch_ref(value)
        ref_key = patch_ref_key(ref)
        if not ref_key or ref_key == key:
            continue
        supersedes.append(ref)
    supersedes = list(dict.fromkeys(supersedes))

    release_date = body.release_date
    if release_date is not None and release_date.tzinfo is None:
        release_date = release_date.replace(tzinfo=timezone.utc)
    eol_date = body.eol_date
    if eol_date is not None and eol_date.tzinfo is None:
        eol_date = eol_date.replace(tzinfo=timezone.utc)
    if release_date and eol_date and eol_date < release_date:
        raise HTTPException(status_code=400, detail="eol_date cannot be before release_date")

    before = {
        "vendor": entry.vendor,
        "product": entry.product,
        "classification": entry.classification,
        "release_date": entry.release_date.isoformat() if entry.release_date else None,
        "eol_date": entry.eol_date.isoformat() if entry.eol_date else None,
        "supersedes": load(entry.supersedes_json, []),
        "lifecycle_source": entry.lifecycle_source,
    }

    if body.vendor is not None:
        entry.vendor = body.vendor.strip()
    if body.product is not None:
        entry.product = body.product.strip()
    if body.classification is not None:
        entry.classification = body.classification.strip().lower()
    entry.release_date = release_date
    entry.eol_date = eol_date
    entry.supersedes_json = dump(supersedes)
    entry.lifecycle_source = body.source.strip().lower()
    entry.lifecycle_updated_by = principal["actor"]
    entry.lifecycle_updated_at = now()
    manual_payload = {
        "vendor": entry.vendor,
        "product": entry.product,
        "classification": entry.classification,
        "release_date": entry.release_date,
        "eol_date": entry.eol_date,
        "supersedes": load(entry.supersedes_json, []),
    }
    apply_patch_metadata_record(
        entry,
        manual_payload,
        source="manual",
        priority=1000,
        observed_at=entry.lifecycle_updated_at,
        expires_at=None,
        actor=principal["actor"],
    )
    db.commit()

    after = {
        "vendor": entry.vendor,
        "product": entry.product,
        "classification": entry.classification,
        "release_date": entry.release_date.isoformat() if entry.release_date else None,
        "eol_date": entry.eol_date.isoformat() if entry.eol_date else None,
        "supersedes": load(entry.supersedes_json, []),
        "lifecycle_source": entry.lifecycle_source,
    }
    audit(
        db,
        principal["actor"],
        "patch_catalog.lifecycle.updated",
        "patch_catalog",
        entry.patch_key,
        {"before": before, "after": after, "reason": body.reason.strip()},
    )
    return {"ok": True, "patch": next(
        item for item in patch_catalog_report(db, limit=2000)["items"]
        if item["patch_key"] == entry.patch_key
    )}



AUTO_PATCH_CONFIDENCE_RANK = {"insufficient_data": 0, "low": 1, "medium": 2, "high": 3}


def serialize_auto_patch_policy(policy: AutoPatchPolicy) -> dict:
    return {
        "id": policy.id,
        "name": policy.name,
        "enabled": policy.enabled,
        "mode": policy.mode,
        "target_os": policy.target_os,
        "target_tag": policy.target_tag,
        "require_kev": policy.require_kev,
        "require_external": policy.require_external,
        "require_patch_tuesday": policy.require_patch_tuesday,
        "min_missing_assets": policy.min_missing_assets,
        "confidence_floor": policy.confidence_floor,
        "allow_eol": policy.allow_eol,
        "superseded_action": policy.superseded_action,
        "ring_percent": policy.ring_percent,
        "require_approval": policy.require_approval,
        "require_health_gate": policy.require_health_gate,
        "require_rollback": policy.require_rollback,
        "created_by": policy.created_by,
        "updated_by": policy.updated_by,
        "created_at": policy.created_at.isoformat() if policy.created_at else None,
        "updated_at": policy.updated_at.isoformat() if policy.updated_at else None,
    }


def _auto_patch_agent_external(db: Session, agent_id: str) -> bool:
    latest = db.query(AssetRiskSnapshot).filter(
        AssetRiskSnapshot.agent_id == agent_id
    ).order_by(AssetRiskSnapshot.captured_at.desc()).first()
    if latest is not None:
        return bool(latest.external)
    profile = db.get(AssetRiskProfile, agent_id)
    if profile is not None and profile.external_override is not None:
        return bool(profile.external_override)
    return False


def _auto_patch_existing_campaign(db: Session, policy_id: str, patch_ref: str):
    for campaign in db.query(Campaign).filter(Campaign.status.in_(["draft", "deployed"])).all():
        payload = load(campaign.payload_json, {})
        if (
            str(payload.get("auto_policy_id") or "") == policy_id
            and str(payload.get("auto_policy_patch_ref") or "").lower() == patch_ref.lower()
        ):
            return campaign
    return None


def _auto_patch_scope_analysis(db: Session, policy: AutoPatchPolicy, item: dict) -> dict:
    patch_key = str(item.get("patch_key") or patch_ref_key(item.get("patch_ref")))
    if not patch_key:
        return {
            "missing_total": 0, "excluded_os": 0, "excluded_tag": 0,
            "excluded_external": 0, "selected": 0, "selected_agents": [], "selected_sample": [],
        }
    agent_ids = [
        row.agent_id
        for row in db.query(PatchApplicability).filter(
            PatchApplicability.patch_key == patch_key,
            PatchApplicability.status == "missing",
        ).all()
    ]
    agents = db.query(Agent).filter(Agent.id.in_(agent_ids)).all() if agent_ids else []
    excluded_os = 0
    excluded_tag = 0
    excluded_external = 0
    selected = []
    for agent in agents:
        if policy.target_os not in {"", "all"} and str(agent.os_family or "").lower() != policy.target_os:
            excluded_os += 1
            continue
        if policy.target_tag:
            tags = {str(x).strip().lower() for x in load(agent.tags, []) if str(x).strip()}
            if policy.target_tag.lower() not in tags:
                excluded_tag += 1
                continue
        if policy.require_external and not _auto_patch_agent_external(db, agent.id):
            excluded_external += 1
            continue
        selected.append(agent)
    selected = sorted(selected, key=lambda x: x.hostname.lower())
    return {
        "missing_total": len(agents),
        "excluded_os": excluded_os,
        "excluded_tag": excluded_tag,
        "excluded_external": excluded_external,
        "selected": len(selected),
        "selected_agents": selected,
        "selected_sample": [
            {
                "agent_id": agent.id,
                "hostname": agent.hostname,
                "os_family": agent.os_family,
                "external": _auto_patch_agent_external(db, agent.id),
            }
            for agent in selected[:20]
        ],
    }


def _auto_patch_policy_agents(db: Session, policy: AutoPatchPolicy, item: dict) -> list[Agent]:
    return _auto_patch_scope_analysis(db, policy, item)["selected_agents"]


def _auto_patch_freeze_windows(db: Session, policy: AutoPatchPolicy, agents: list[Agent]) -> list[dict]:
    if not agents:
        return []
    os_values = {str(agent.os_family or "all").lower() for agent in agents}
    target_os = policy.target_os if policy.target_os not in {"", "all"} else (
        next(iter(os_values)) if len(os_values) == 1 else "all"
    )
    probe = Campaign(
        id=f"policy-probe-{policy.id}",
        name="policy-probe",
        target_os=target_os,
        target_tag=policy.target_tag,
        ring_percent=policy.ring_percent,
        action="install_updates",
        payload_json="{}",
        status="draft",
    )
    return [serialize_freeze_window(x) for x in active_freeze_windows_for_campaign(db, probe)]


def _auto_patch_blockers(db: Session, patch_ref: str, agents: list[Agent]) -> list[dict]:
    blockers = []
    for rule in active_patch_block_rules(db):
        matched = [agent for agent in agents if patch_block_rule_matches(rule, patch_ref, agent)]
        if matched:
            blockers.append({
                "rule_id": rule.id,
                "rule_name": rule.name,
                "patch_ref": rule.patch_ref,
                "reason": rule.reason,
                "matched_assets": len(matched),
            })
    return blockers


def auto_patch_policy_report(db: Session, create_drafts: bool = False, actor: str = "system:auto-patch") -> dict:
    catalog = patch_catalog_report(db, limit=2000)
    items = catalog.get("items", [])
    item_by_ref = {str(item.get("patch_ref") or "").lower(): item for item in items}
    policies = db.query(AutoPatchPolicy).filter(AutoPatchPolicy.enabled.is_(True)).order_by(AutoPatchPolicy.name.asc()).all()
    decisions = []
    created = 0

    for policy in policies:
        seen_effective = set()
        for original in items:
            reasons = []
            effective = original
            effective_ref = str(original.get("patch_ref") or "")
            if not effective_ref:
                continue
            threat = original.get("threat") or {}
            lifecycle = original.get("lifecycle") or {}
            supersedence = original.get("supersedence") or {}

            if policy.require_kev and int(threat.get("kev_findings") or 0) <= 0:
                continue
            if policy.require_patch_tuesday and not bool(lifecycle.get("patch_tuesday")):
                continue
            if int((original.get("states") or {}).get("missing") or 0) < int(policy.min_missing_assets):
                continue

            if supersedence.get("obsolete"):
                if policy.superseded_action == "skip":
                    decisions.append({
                        "policy_id": policy.id, "policy_name": policy.name, "patch_ref": effective_ref,
                        "status": "skipped_superseded",
                        "reasons": ["patch superseded and policy is configured to skip"],
                    })
                    continue
                if policy.superseded_action == "replace":
                    replacement = str(supersedence.get("preferred_replacement") or "")
                    replacement_item = item_by_ref.get(replacement.lower()) if replacement else None
                    if not replacement_item or int((replacement_item.get("states") or {}).get("missing") or 0) <= 0:
                        decisions.append({
                            "policy_id": policy.id, "policy_name": policy.name, "patch_ref": effective_ref,
                            "status": "review_replacement",
                            "reasons": ["preferred replacement is not observed as applicable/missing"],
                            "preferred_replacement": replacement or None,
                        })
                        continue
                    effective = replacement_item
                    effective_ref = replacement
                    reasons.append(f"superseded patch replaced by observed leaf {replacement}")

            effective_key = effective_ref.lower()
            if effective_key in seen_effective:
                continue
            seen_effective.add(effective_key)

            lifecycle = effective.get("lifecycle") or {}
            if lifecycle.get("eol_state") == "eol" and not policy.allow_eol:
                decisions.append({
                    "policy_id": policy.id, "policy_name": policy.name, "patch_ref": effective_ref,
                    "status": "blocked_eol", "reasons": reasons + ["EOL is blocked by policy"],
                })
                continue

            scope = _auto_patch_scope_analysis(db, policy, effective)
            agents = scope["selected_agents"]
            confidence = (effective.get("patch_confidence") or {}).get("confidence") or "insufficient_data"
            if AUTO_PATCH_CONFIDENCE_RANK.get(confidence, 0) < AUTO_PATCH_CONFIDENCE_RANK.get(policy.confidence_floor, 0):
                decisions.append({
                    "policy_id": policy.id, "policy_name": policy.name, "patch_ref": effective_ref,
                    "status": "hold_confidence",
                    "scope": {k: v for k, v in scope.items() if k != "selected_agents"},
                    "reasons": reasons + [f"confidence {confidence} is below floor {policy.confidence_floor}"],
                })
                continue

            if len(agents) < int(policy.min_missing_assets):
                continue
            external_count = sum(1 for agent in agents if _auto_patch_agent_external(db, agent.id))
            blockers = _auto_patch_blockers(db, effective_ref, agents)
            freezes = _auto_patch_freeze_windows(db, policy, agents)

            if blockers:
                decisions.append({
                    "policy_id": policy.id, "policy_name": policy.name, "patch_ref": effective_ref,
                    "status": "blocked_patch_guard", "assets": len(agents),
                    "reasons": reasons + ["Patch Guard matched the selected patch/assets"], "blockers": blockers,
                })
                continue
            if freezes:
                decisions.append({
                    "policy_id": policy.id, "policy_name": policy.name, "patch_ref": effective_ref,
                    "status": "blocked_change_freeze", "assets": len(agents),
                    "reasons": reasons + ["active Change Freeze matched policy scope"], "freeze_windows": freezes,
                })
                continue
            if len(agents) > 500:
                decisions.append({
                    "policy_id": policy.id, "policy_name": policy.name, "patch_ref": effective_ref,
                    "status": "review_scope_size", "assets": len(agents),
                    "reasons": reasons + ["target snapshot exceeds 500 agents; split policy scope before drafting"],
                })
                continue

            effective_threat = effective.get("threat") or {}
            effective_lifecycle = effective.get("lifecycle") or {}
            kev = int(effective_threat.get("kev_findings") or 0) > 0
            patch_tuesday = bool(effective_lifecycle.get("patch_tuesday"))
            ring_percent = int(policy.ring_percent)
            if kev and external_count:
                ring_percent = min(ring_percent, 5)
                reasons.append("KEV + external exposure forces emergency 5% canary")
            elif patch_tuesday:
                ring_percent = min(ring_percent, 10)
                reasons.append("Patch Tuesday keeps rollout in pilot ring")

            approval_required = bool(policy.require_approval or kev or external_count)
            health_gate = bool(policy.require_health_gate or confidence in {"insufficient_data", "low"})
            rollback_required = bool(policy.require_rollback)
            existing = _auto_patch_existing_campaign(db, policy.id, effective_ref)
            decision = {
                "policy_id": policy.id, "policy_name": policy.name, "mode": policy.mode,
                "patch_ref": effective_ref, "source_patch_ref": original.get("patch_ref"),
                "assets": len(agents), "external_assets": external_count,
                "kev": kev, "patch_tuesday": patch_tuesday, "confidence": confidence,
                "ring_percent": ring_percent, "approval_required": approval_required,
                "health_gate_required": health_gate, "rollback_required": rollback_required,
                "status": "recommend", "reasons": reasons or ["policy conditions matched"],
                "existing_campaign_id": existing.id if existing else None,
                "scope": {k: v for k, v in scope.items() if k != "selected_agents"},
                "blast_radius": {
                    "selected_assets": len(agents),
                    "initial_ring_assets": max(1, math.ceil(len(agents) * ring_percent / 100)) if agents else 0,
                    "initial_ring_percent": ring_percent,
                },
            }

            if policy.mode == "draft" and create_drafts and not existing:
                target_os_values = {str(agent.os_family or "all").lower() for agent in agents}
                target_os = policy.target_os if policy.target_os not in {"", "all"} else (
                    next(iter(target_os_values)) if len(target_os_values) == 1 else "all"
                )
                body = CampaignCreate(
                    name=f"[AUTO] {policy.name} · {effective_ref}",
                    description="Auto Patch Policy draft: " + " · ".join(decision["reasons"]),
                    target_os=target_os,
                    target_tag=policy.target_tag,
                    ring_percent=ring_percent,
                    action="install_updates",
                    payload={
                        "packages": [effective_ref],
                        "auto_policy_id": policy.id,
                        "auto_policy_name": policy.name,
                        "auto_policy_patch_ref": effective_ref,
                    },
                    reboot_policy="never",
                    post_patch_validation=True,
                    health_gate_enabled=health_gate,
                    health_gate_require_telemetry=True,
                    prepare_rollback=True,
                    rollback_required=rollback_required,
                    target_agent_ids=[agent.id for agent in agents],
                    approval_required=approval_required,
                    approval_reason=(f"Auto Patch Policy {policy.name}: govern deployment of {effective_ref}" if approval_required else ""),
                )
                created_campaign = create_campaign(body, principal={"actor": actor, "role": "operator"}, db=db)
                decision["status"] = "draft_created"
                decision["campaign_id"] = created_campaign["id"]
                created += 1
            elif existing:
                decision["status"] = "draft_exists"
            elif policy.mode == "draft":
                decision["status"] = "draft_ready"
            decisions.append(decision)

    status_counts = {}
    for item in decisions:
        status = item.get("status") or "unknown"
        status_counts[status] = status_counts.get(status, 0) + 1
    return {
        "generated_at": now().isoformat(),
        "summary": {
            "policies": len(policies), "decisions": len(decisions), "drafts_created": created,
            "blocked": sum(v for k, v in status_counts.items() if str(k).startswith("blocked_")),
            "holds": sum(v for k, v in status_counts.items() if str(k).startswith("hold_") or str(k).startswith("review_")),
            "ready": status_counts.get("draft_ready", 0) + status_counts.get("recommend", 0),
            "status_counts": status_counts,
        },
        "policies": [serialize_auto_patch_policy(policy) for policy in policies],
        "decisions": decisions,
    }




def serialize_auto_patch_evaluation(item: AutoPatchEvaluation, include_result: bool = False) -> dict:
    data = {
        "id": item.id,
        "actor": item.actor,
        "create_drafts": item.create_drafts,
        "policies": item.policies,
        "decisions": item.decisions,
        "drafts_created": item.drafts_created,
        "blocked": item.blocked,
        "holds": item.holds,
        "ready": item.ready,
        "summary": load(item.summary_json, {}),
        "created_at": item.created_at.isoformat() if item.created_at else None,
    }
    if include_result:
        data["result"] = load(item.result_json, {})
    return data


def persist_auto_patch_evaluation(db: Session, result: dict, actor: str, create_drafts: bool) -> AutoPatchEvaluation:
    summary = result.get("summary") or {}
    item = AutoPatchEvaluation(
        id=str(uuid.uuid4()),
        actor=actor,
        create_drafts=create_drafts,
        policies=int(summary.get("policies") or 0),
        decisions=int(summary.get("decisions") or 0),
        drafts_created=int(summary.get("drafts_created") or 0),
        blocked=int(summary.get("blocked") or 0),
        holds=int(summary.get("holds") or 0),
        ready=int(summary.get("ready") or 0),
        summary_json=dump(summary),
        result_json=dump(result),
    )
    db.add(item)
    db.commit()
    return item


def auto_patch_simulation(db: Session, policy: AutoPatchPolicy, patch_ref: str) -> dict:
    catalog = patch_catalog_report(db, limit=2000)
    item = next(
        (x for x in catalog.get("items", []) if str(x.get("patch_ref") or "").lower() == patch_ref.lower()),
        None,
    )
    if not item:
        raise HTTPException(status_code=404, detail="patch not found in catalog")
    threat = item.get("threat") or {}
    lifecycle = item.get("lifecycle") or {}
    scope = _auto_patch_scope_analysis(db, policy, item)
    report = auto_patch_policy_report(db, create_drafts=False)
    decision = next(
        (
            x for x in report.get("decisions", [])
            if x.get("policy_id") == policy.id
            and (
                str(x.get("patch_ref") or "").lower() == patch_ref.lower()
                or str(x.get("source_patch_ref") or "").lower() == patch_ref.lower()
            )
        ),
        None,
    )
    preconditions = {
        "kev": {
            "required": policy.require_kev,
            "actual": int(threat.get("kev_findings") or 0) > 0,
        },
        "external": {
            "required": policy.require_external,
            "selected_external": sum(1 for x in scope["selected_agents"] if _auto_patch_agent_external(db, x.id)),
        },
        "patch_tuesday": {
            "required": policy.require_patch_tuesday,
            "actual": bool(lifecycle.get("patch_tuesday")),
        },
        "minimum_missing": {
            "required": policy.min_missing_assets,
            "actual_selected": scope["selected"],
        },
        "confidence": {
            "required": policy.confidence_floor,
            "actual": (item.get("patch_confidence") or {}).get("confidence") or "insufficient_data",
        },
        "eol": {
            "allowed": policy.allow_eol,
            "state": lifecycle.get("eol_state") or "unknown",
        },
    }
    return {
        "generated_at": now().isoformat(),
        "policy": serialize_auto_patch_policy(policy),
        "patch": {
            "patch_ref": item.get("patch_ref"),
            "title": item.get("title"),
            "vendor": item.get("vendor"),
            "product": item.get("product"),
            "severity": item.get("severity"),
        },
        "scope": {k: v for k, v in scope.items() if k != "selected_agents"},
        "preconditions": preconditions,
        "decision": decision,
        "matched": decision is not None,
    }


@app.get("/api/admin/auto-patch/policies")
def list_auto_patch_policies(_=Depends(require_viewer), db: Session = Depends(get_db)):
    return [serialize_auto_patch_policy(x) for x in db.query(AutoPatchPolicy).order_by(AutoPatchPolicy.name.asc()).all()]


@app.post("/api/admin/auto-patch/policies")
def create_auto_patch_policy(body: AutoPatchPolicyCreate, principal=Depends(require_admin), db: Session = Depends(get_db)):
    name = body.name.strip()
    if db.query(AutoPatchPolicy).filter(func.lower(AutoPatchPolicy.name) == name.lower()).first():
        raise HTTPException(status_code=409, detail="auto patch policy name already exists")
    policy = AutoPatchPolicy(
        id=str(uuid.uuid4()), name=name, enabled=body.enabled, mode=body.mode,
        target_os=body.target_os.strip().lower(), target_tag=body.target_tag.strip(),
        require_kev=body.require_kev, require_external=body.require_external,
        require_patch_tuesday=body.require_patch_tuesday, min_missing_assets=body.min_missing_assets,
        confidence_floor=body.confidence_floor, allow_eol=body.allow_eol,
        superseded_action=body.superseded_action, ring_percent=body.ring_percent,
        require_approval=body.require_approval, require_health_gate=body.require_health_gate,
        require_rollback=body.require_rollback, created_by=principal["actor"], updated_by=principal["actor"],
    )
    db.add(policy)
    db.commit()
    audit(db, principal["actor"], "auto_patch_policy.created", "auto_patch_policy", policy.id, serialize_auto_patch_policy(policy))
    return serialize_auto_patch_policy(policy)


@app.patch("/api/admin/auto-patch/policies/{policy_id}")
def update_auto_patch_policy(policy_id: str, body: AutoPatchPolicyUpdate, principal=Depends(require_admin), db: Session = Depends(get_db)):
    policy = db.get(AutoPatchPolicy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="auto patch policy not found")
    before = serialize_auto_patch_policy(policy)
    for field in (
        "enabled", "mode", "target_os", "target_tag", "require_kev", "require_external",
        "require_patch_tuesday", "min_missing_assets", "confidence_floor", "allow_eol",
        "superseded_action", "ring_percent", "require_approval", "require_health_gate", "require_rollback"
    ):
        value = getattr(body, field)
        if value is not None:
            if field == "target_os":
                value = value.strip().lower()
            if field == "target_tag":
                value = value.strip()
            setattr(policy, field, value)
    policy.updated_by = principal["actor"]
    db.commit()
    after = serialize_auto_patch_policy(policy)
    audit(db, principal["actor"], "auto_patch_policy.updated", "auto_patch_policy", policy.id, {"before": before, "after": after})
    return after


@app.get("/api/admin/reports/auto-patch-decisions")
def auto_patch_decisions(_=Depends(require_viewer), db: Session = Depends(get_db)):
    return auto_patch_policy_report(db, create_drafts=False)


@app.post("/api/admin/auto-patch/evaluate")
def evaluate_auto_patch(create_drafts: bool = False, principal=Depends(require_operator), db: Session = Depends(get_db)):
    result = auto_patch_policy_report(db, create_drafts=create_drafts, actor=principal["actor"])
    ledger = persist_auto_patch_evaluation(db, result, principal["actor"], create_drafts)
    audit(db, principal["actor"], "auto_patch_policy.evaluated", "auto_patch_policy", ledger.id, {
        "create_drafts": create_drafts, "summary": result["summary"]
    })
    return {**result, "evaluation_id": ledger.id}


@app.get("/api/admin/auto-patch/history")
def auto_patch_history(limit: int = 50, _=Depends(require_viewer), db: Session = Depends(get_db)):
    items = db.query(AutoPatchEvaluation).order_by(AutoPatchEvaluation.created_at.desc()).limit(max(1, min(limit, 200))).all()
    return [serialize_auto_patch_evaluation(item) for item in items]


@app.get("/api/admin/auto-patch/history/{evaluation_id}")
def auto_patch_history_detail(evaluation_id: str, _=Depends(require_viewer), db: Session = Depends(get_db)):
    item = db.get(AutoPatchEvaluation, evaluation_id)
    if not item:
        raise HTTPException(status_code=404, detail="auto patch evaluation not found")
    return serialize_auto_patch_evaluation(item, include_result=True)


@app.post("/api/admin/auto-patch/simulate")
def simulate_auto_patch(body: AutoPatchSimulationRequest, _=Depends(require_viewer), db: Session = Depends(get_db)):
    policy = db.get(AutoPatchPolicy, body.policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="auto patch policy not found")
    return auto_patch_simulation(db, policy, body.patch_ref)


@app.get("/api/admin/reports/patch-catalog")
def admin_patch_catalog(
    limit: int = 500,
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    return patch_catalog_report(db, limit=limit)


@app.get("/api/admin/reports/patch-confidence")
def patch_confidence(
    limit: int = 200,
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    return patch_confidence_report(db, limit=limit)


@app.get("/api/admin/remediation-projects/{project_id}/history")
def get_remediation_project_history(
    project_id: str,
    limit: int = 200,
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    return remediation_project_history(db, project_id, limit)


@app.get("/api/admin/remediation-projects")
def list_remediation_projects(
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    return remediation_projects_report(db)


@app.post("/api/admin/remediation-projects")
def create_remediation_project(
    body: RemediationProjectCreate,
    principal=Depends(require_operator),
    db: Session = Depends(get_db),
):
    name = body.name.strip()
    patch_ref = body.patch_ref.strip()
    scope_mode = body.scope_mode.strip().lower()
    scope_tag = body.scope_tag.strip().lower()
    scope_filter = {}
    for key, value in (
        ("business_service", body.scope_business_service),
        ("environment", body.scope_environment),
        ("owner", body.scope_owner),
    ):
        normalized = str(value or "").strip()
        if normalized:
            scope_filter[key] = normalized
    if body.scope_external is not None:
        scope_filter["external"] = bool(body.scope_external)
    if body.scope_min_criticality is not None:
        scope_filter["min_criticality"] = int(body.scope_min_criticality)
    owner = body.owner.strip()
    reason = body.reason.strip()
    if len(name) < 3:
        raise HTTPException(status_code=400, detail="project name must contain at least 3 non-space characters")
    if not patch_ref:
        raise HTTPException(status_code=400, detail="patch reference is required")
    if scope_mode not in {"static", "dynamic"}:
        raise HTTPException(status_code=400, detail="scope mode must be static or dynamic")
    if len(owner) < 2:
        raise HTTPException(status_code=400, detail="project owner must contain at least 2 non-space characters")
    if len(reason) < 5:
        raise HTTPException(status_code=400, detail="project reason must contain at least 5 non-space characters")
    if db.query(RemediationProject).filter(RemediationProject.name == name).first():
        raise HTTPException(status_code=409, detail="remediation project name already exists")

    due_at = body.due_at
    if due_at.tzinfo is None:
        due_at = due_at.replace(tzinfo=timezone.utc)
    reference = now()
    if due_at <= reference:
        raise HTTPException(status_code=400, detail="project due date must be in the future")
    if due_at > reference + timedelta(days=1095):
        raise HTTPException(status_code=400, detail="project due date cannot exceed 3 years")

    findings = _remediation_project_open_findings(
        db,
        patch_ref,
        scope_tag,
        scope_filter,
    )
    if not findings:
        raise HTTPException(status_code=409, detail="project scope has no open findings for this patch reference")

    finding_ids = sorted({finding.id for finding in findings})
    agent_ids = sorted({
        finding.agent_id for finding in findings
        if finding.agent_id
    })
    cves = sorted({
        finding.cve for finding in findings
        if finding.cve
    })
    project = RemediationProject(
        id=str(uuid.uuid4()),
        name=name,
        patch_ref=patch_ref,
        scope_mode=scope_mode,
        scope_tag=scope_tag,
        scope_filter_json=dump(scope_filter),
        owner=owner,
        due_at=due_at,
        status="active",
        baseline_findings=len(finding_ids),
        baseline_assets=len(agent_ids),
        baseline_risk_reduction=_remediation_project_risk_reduction(findings, reference),
        scope_snapshot_json=dump({
            "finding_ids": finding_ids,
            "agent_ids": agent_ids,
            "cves": cves,
            "scope_filter": scope_filter,
            "captured_at": reference.isoformat(),
        }),
        reason=reason,
        created_by=principal["actor"],
        updated_by=principal["actor"],
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    result = serialize_remediation_project(db, project, reference)
    capture_remediation_project_snapshots(
        db, source=f"project_created:{principal['actor']}",
        reference=reference, minimum_interval_seconds=0,
        project_ids={project.id},
    )
    audit(
        db,
        principal["actor"],
        "remediation_project.created",
        "remediation_project",
        project.id,
        result,
    )
    return {"ok": True, "project": result}


@app.put("/api/admin/remediation-projects/{project_id}")
def update_remediation_project(
    project_id: str,
    body: RemediationProjectUpdate,
    principal=Depends(require_operator),
    db: Session = Depends(get_db),
):
    project = db.query(RemediationProject).filter(
        RemediationProject.id == project_id
    ).with_for_update().first()
    if not project:
        raise HTTPException(status_code=404, detail="remediation project not found")

    before = serialize_remediation_project(db, project)
    reason = body.reason.strip()
    if len(reason) < 5:
        raise HTTPException(status_code=400, detail="project reason must contain at least 5 non-space characters")

    if body.owner is not None:
        owner = body.owner.strip()
        if len(owner) < 2:
            raise HTTPException(status_code=400, detail="project owner must contain at least 2 non-space characters")
        project.owner = owner

    if body.due_at is not None:
        due_at = body.due_at
        if due_at.tzinfo is None:
            due_at = due_at.replace(tzinfo=timezone.utc)
        project.due_at = due_at

    if body.status is not None:
        status = body.status.strip().lower()
        if status not in {"active", "awaiting_verification", "completed", "cancelled"}:
            raise HTTPException(status_code=400, detail="unsupported remediation project status")
        current = serialize_remediation_project(db, project)
        if status == "completed" and current["tracked_open_findings"] > 0:
            raise HTTPException(status_code=409, detail="project cannot be completed while tracked findings remain open")
        if status == "completed":
            project.completed_at = now()
        elif status in {"active", "awaiting_verification"}:
            due_at = project.due_at
            if due_at.tzinfo is None:
                due_at = due_at.replace(tzinfo=timezone.utc)
            if due_at <= now():
                raise HTTPException(status_code=409, detail="expired project requires a future due date before reactivation")
            project.completed_at = None
        else:
            project.completed_at = None
        project.status = status

    project.reason = reason
    project.updated_by = principal["actor"]
    project.updated_at = now()
    db.commit()
    db.refresh(project)
    after = serialize_remediation_project(db, project)
    capture_remediation_project_snapshots(
        db, source=f"project_updated:{principal['actor']}",
        minimum_interval_seconds=0, project_ids={project.id},
    )
    audit(
        db,
        principal["actor"],
        "remediation_project.updated",
        "remediation_project",
        project.id,
        {"before": before, "after": after},
    )
    return {"ok": True, "project": after}


@app.get("/api/admin/reports/remediation-hub")
def remediation_hub(
    limit: int = 100,
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    return remediation_hub_report(db, limit=limit)


@app.get("/api/admin/reports/risk-reduction-opportunities")
def risk_reduction_opportunities(
    limit: int = 100,
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    return risk_reduction_opportunities_report(db, limit=limit)


@app.get("/api/admin/reports/remediation-queue")
def remediation_queue(
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    return remediation_queue_report(db)


@app.get("/api/admin/reports/vulnerability-sla")
def admin_vulnerability_sla_report(_=Depends(require_viewer), db: Session = Depends(get_db)):
    return vulnerability_sla_report(db)


@app.post("/api/admin/agents/{agent_id}/risk-simulation")
def simulate_asset_risk_reduction(
    agent_id: str,
    body: AssetRiskSimulationRequest,
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")

    requested_ids = list(dict.fromkeys(body.finding_ids))
    findings = list(agent.vulnerabilities or [])
    finding_map = {finding.id: finding for finding in findings}
    missing = [finding_id for finding_id in requested_ids if finding_id not in finding_map]
    if missing:
        raise HTTPException(
            status_code=400,
            detail={"message": "finding does not belong to asset", "finding_ids": missing},
        )

    reference = now()
    before = asset_risk_score(agent, findings, reference)
    excluded = set(requested_ids)
    simulated_findings = [
        finding for finding in findings
        if finding.id not in excluded
    ]
    after = asset_risk_score(agent, simulated_findings, reference)

    delta = round(max(0.0, before["score"] - after["score"]), 1)
    reduction_percent = (
        round((delta / before["score"]) * 100.0, 1)
        if before["score"] > 0
        else 0.0
    )

    policy = effective_asset_risk_policy(db, agent)
    return {
        "generated_at": reference.isoformat(),
        "mode": "simulation_only",
        "asset": {
            "agent_id": agent.id,
            "hostname": agent.hostname,
        },
        "excluded_findings": requested_ids,
        "before": {
            "score": before["score"],
            "level": before["level"],
            "open_findings": before["open_findings"],
            "above_risk_appetite": before["score"] >= policy["risk_appetite"],
        },
        "after": {
            "score": after["score"],
            "level": after["level"],
            "open_findings": after["open_findings"],
            "above_risk_appetite": after["score"] >= policy["risk_appetite"],
        },
        "impact": {
            "delta": delta,
            "reduction_percent": reduction_percent,
            "crosses_below_appetite": (
                before["score"] >= policy["risk_appetite"]
                and after["score"] < policy["risk_appetite"]
            ),
        },
        "risk_appetite": policy["risk_appetite"],
        "risk_policy": policy,
        "note": "Simulation does not modify finding status, evidence, campaign state, or Asset Risk history.",
    }


@app.get("/api/admin/agents/{agent_id}/risk-treatments")
def list_asset_risk_treatments(
    agent_id: str,
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    return [
        serialize_asset_risk_treatment(item)
        for item in sorted(
            agent.risk_treatments or [],
            key=lambda treatment: treatment.created_at or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )
    ]


@app.post("/api/admin/agents/{agent_id}/risk-treatments")
def create_asset_risk_treatment(
    agent_id: str,
    body: AssetRiskTreatmentCreate,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    agent = db.query(Agent).filter(Agent.id == agent_id).with_for_update().first()
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")

    owner = body.owner.strip()
    action = body.action.strip()
    if len(owner) < 2:
        raise HTTPException(status_code=400, detail="risk treatment owner must contain at least 2 non-space characters")
    if len(action) < 5:
        raise HTTPException(status_code=400, detail="risk treatment action must contain at least 5 non-space characters")

    due_at = body.due_at
    if due_at.tzinfo is None:
        due_at = due_at.replace(tzinfo=timezone.utc)
    if due_at <= now():
        raise HTTPException(status_code=400, detail="risk treatment due date must be in the future")

    require_asset_above_risk_appetite(db, agent)
    existing = active_asset_risk_treatment(agent)
    if existing:
        raise HTTPException(
            status_code=409,
            detail={"message": "asset already has an active treatment plan", "id": existing.id},
        )

    treatment = AssetRiskTreatment(
        id=str(uuid.uuid4()),
        agent=agent,
        owner=owner,
        action=action,
        due_at=due_at,
        status="planned",
        created_by=principal["actor"],
        updated_by=principal["actor"],
    )
    db.add(treatment)
    db.commit()
    db.refresh(treatment)

    result = serialize_asset_risk_treatment(treatment)
    snapshot = capture_asset_risk_snapshots(
        db,
        source=f"risk_treatment:{principal['actor']}",
        minimum_interval_seconds=0,
        agent_ids={agent.id},
    )
    audit(
        db,
        principal["actor"],
        "asset_risk.treatment.created",
        "agent",
        agent.id,
        {"treatment": result, "snapshot": snapshot},
    )
    return {"ok": True, "treatment": result}


@app.put("/api/admin/agents/{agent_id}/risk-treatments/{treatment_id}")
def update_asset_risk_treatment(
    agent_id: str,
    treatment_id: str,
    body: AssetRiskTreatmentUpdate,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    treatment = db.get(AssetRiskTreatment, treatment_id)
    if not treatment or treatment.agent_id != agent.id:
        raise HTTPException(status_code=404, detail="risk treatment not found")

    before = serialize_asset_risk_treatment(treatment)
    allowed_statuses = {"planned", "in_progress", "completed", "cancelled"}
    if body.status is not None and body.status not in allowed_statuses:
        raise HTTPException(status_code=400, detail="unsupported risk treatment status")

    if body.owner is not None:
        owner = body.owner.strip()
        if len(owner) < 2:
            raise HTTPException(status_code=400, detail="risk treatment owner must contain at least 2 non-space characters")
        treatment.owner = owner
    if body.action is not None:
        action = body.action.strip()
        if len(action) < 5:
            raise HTTPException(status_code=400, detail="risk treatment action must contain at least 5 non-space characters")
        treatment.action = action
    if body.due_at is not None:
        due_at = body.due_at
        if due_at.tzinfo is None:
            due_at = due_at.replace(tzinfo=timezone.utc)
        if due_at <= now() and (body.status or treatment.status) not in {"completed", "cancelled"}:
            raise HTTPException(status_code=400, detail="active risk treatment due date must be in the future")
        treatment.due_at = due_at
    if body.completion_evidence is not None:
        treatment.completion_evidence = body.completion_evidence.strip()
    if body.status is not None:
        if body.status == "completed":
            evidence = (
                body.completion_evidence.strip()
                if body.completion_evidence is not None
                else treatment.completion_evidence.strip()
            )
            if len(evidence) < 5:
                raise HTTPException(
                    status_code=400,
                    detail="completion evidence is required to complete a treatment plan",
                )
            treatment.completion_evidence = evidence
            treatment.completed_at = now()
        elif treatment.status == "completed" and body.status != "completed":
            raise HTTPException(status_code=409, detail="completed treatment plans cannot be reopened")
        else:
            treatment.completed_at = None
        treatment.status = body.status

    treatment.updated_by = principal["actor"]
    treatment.updated_at = now()
    db.commit()
    db.refresh(treatment)

    after = serialize_asset_risk_treatment(treatment)
    snapshot = capture_asset_risk_snapshots(
        db,
        source=f"risk_treatment_updated:{principal['actor']}",
        minimum_interval_seconds=0,
        agent_ids={agent.id},
    )
    audit(
        db,
        principal["actor"],
        "asset_risk.treatment.updated",
        "agent",
        agent.id,
        {"before": before, "after": after, "snapshot": snapshot},
    )
    return {"ok": True, "treatment": after}


@app.get("/api/admin/agents/{agent_id}/risk-acceptances")
def list_asset_risk_acceptances(
    agent_id: str,
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    return [
        serialize_asset_risk_acceptance(item)
        for item in sorted(
            agent.risk_acceptances or [],
            key=lambda acceptance: acceptance.created_at or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )
    ]


@app.post("/api/admin/agents/{agent_id}/risk-acceptances")
def create_asset_risk_acceptance(
    agent_id: str,
    body: AssetRiskAcceptanceCreate,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    agent = db.query(Agent).filter(Agent.id == agent_id).with_for_update().first()
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")

    reason = body.reason.strip()
    if len(reason) < 5:
        raise HTTPException(status_code=400, detail="risk acceptance reason must contain at least 5 non-space characters")

    expires_at = body.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    current = now()
    if expires_at <= current:
        raise HTTPException(status_code=400, detail="risk acceptance must expire in the future")
    if expires_at > current + timedelta(days=365):
        raise HTTPException(status_code=400, detail="risk acceptance cannot exceed 365 days")

    require_asset_above_risk_appetite(db, agent, current)
    existing = active_asset_risk_acceptance(agent, current)
    if existing:
        raise HTTPException(
            status_code=409,
            detail={"message": "asset already has an active risk acceptance", "id": existing.id},
        )

    acceptance = AssetRiskAcceptance(
        id=str(uuid.uuid4()),
        agent=agent,
        reason=reason,
        approved_by=principal["actor"],
        expires_at=expires_at,
    )
    db.add(acceptance)
    db.commit()
    db.refresh(acceptance)

    result = serialize_asset_risk_acceptance(acceptance)
    snapshot = capture_asset_risk_snapshots(
        db,
        source=f"risk_acceptance:{principal['actor']}",
        minimum_interval_seconds=0,
        agent_ids={agent.id},
    )
    audit(
        db,
        principal["actor"],
        "asset_risk.acceptance.created",
        "agent",
        agent.id,
        {"acceptance": result, "snapshot": snapshot},
    )
    return {"ok": True, "acceptance": result}


@app.post("/api/admin/agents/{agent_id}/risk-acceptances/{acceptance_id}/revoke")
def revoke_asset_risk_acceptance(
    agent_id: str,
    acceptance_id: str,
    body: AssetRiskAcceptanceRevoke,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    acceptance = db.get(AssetRiskAcceptance, acceptance_id)
    if not acceptance or acceptance.agent_id != agent.id:
        raise HTTPException(status_code=404, detail="risk acceptance not found")
    if acceptance.revoked_at is not None:
        raise HTTPException(status_code=409, detail="risk acceptance already revoked")

    revoke_reason = body.reason.strip()
    if len(revoke_reason) < 5:
        raise HTTPException(status_code=400, detail="revoke reason must contain at least 5 non-space characters")

    acceptance.revoked_at = now()
    acceptance.revoked_by = principal["actor"]
    acceptance.revoke_reason = revoke_reason
    db.commit()
    db.refresh(acceptance)

    result = serialize_asset_risk_acceptance(acceptance)
    snapshot = capture_asset_risk_snapshots(
        db,
        source=f"risk_acceptance_revoked:{principal['actor']}",
        minimum_interval_seconds=0,
        agent_ids={agent.id},
    )
    audit(
        db,
        principal["actor"],
        "asset_risk.acceptance.revoked",
        "agent",
        agent.id,
        {"acceptance": result, "snapshot": snapshot},
    )
    return {"ok": True, "acceptance": result}


@app.get("/api/admin/risk-policies")
def list_asset_risk_policies(
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    return [
        serialize_asset_risk_policy(policy)
        for policy in db.query(AssetRiskPolicy).order_by(
            AssetRiskPolicy.priority.desc(),
            AssetRiskPolicy.name.asc(),
        ).all()
    ]


@app.post("/api/admin/risk-policies")
def create_asset_risk_policy(
    body: AssetRiskPolicyCreate,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    name = body.name.strip()
    target_tag = body.target_tag.strip().lower()
    reason = body.reason.strip()
    if len(name) < 3:
        raise HTTPException(status_code=400, detail="risk policy name must contain at least 3 non-space characters")
    if not target_tag:
        raise HTTPException(status_code=400, detail="risk policy target tag is required")
    if len(reason) < 5:
        raise HTTPException(status_code=400, detail="risk policy reason must contain at least 5 non-space characters")
    if db.query(AssetRiskPolicy).filter(AssetRiskPolicy.name == name).first():
        raise HTTPException(status_code=409, detail="risk policy name already exists")

    policy = AssetRiskPolicy(
        id=str(uuid.uuid4()),
        name=name,
        target_tag=target_tag,
        risk_appetite=body.risk_appetite,
        priority=body.priority,
        enabled=body.enabled,
        reason=reason,
        created_by=principal["actor"],
        updated_by=principal["actor"],
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    affected_agent_ids = agent_ids_matching_risk_tags(db, {policy.target_tag})
    snapshot = (
        capture_asset_risk_snapshots(
            db,
            source=f"risk_policy:{principal['actor']}",
            minimum_interval_seconds=0,
            agent_ids=affected_agent_ids,
        )
        if affected_agent_ids
        else {"created": 0, "skipped": 0, "pruned": 0}
    )
    audit(
        db,
        principal["actor"],
        "asset_risk.policy.created",
        "asset_risk_policy",
        policy.id,
        {"policy": serialize_asset_risk_policy(policy), "affected_agents": len(affected_agent_ids), "snapshot": snapshot},
    )
    return {"ok": True, "policy": serialize_asset_risk_policy(policy)}


@app.put("/api/admin/risk-policies/{policy_id}")
def update_asset_risk_policy(
    policy_id: str,
    body: AssetRiskPolicyUpdate,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    policy = db.get(AssetRiskPolicy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="risk policy not found")

    before = serialize_asset_risk_policy(policy)
    previous_target_tag = str(policy.target_tag or "").strip().lower()
    if body.name is not None:
        name = body.name.strip()
        if len(name) < 3:
            raise HTTPException(status_code=400, detail="risk policy name must contain at least 3 non-space characters")
        duplicate = db.query(AssetRiskPolicy).filter(
            AssetRiskPolicy.name == name,
            AssetRiskPolicy.id != policy.id,
        ).first()
        if duplicate:
            raise HTTPException(status_code=409, detail="risk policy name already exists")
        policy.name = name
    if body.target_tag is not None:
        target_tag = body.target_tag.strip().lower()
        if not target_tag:
            raise HTTPException(status_code=400, detail="risk policy target tag is required")
        policy.target_tag = target_tag
    if body.risk_appetite is not None:
        policy.risk_appetite = body.risk_appetite
    if body.priority is not None:
        policy.priority = body.priority
    if body.enabled is not None:
        policy.enabled = body.enabled
    reason = body.reason.strip()
    if len(reason) < 5:
        raise HTTPException(status_code=400, detail="risk policy reason must contain at least 5 non-space characters")
    policy.reason = reason
    policy.updated_by = principal["actor"]
    policy.updated_at = now()
    db.commit()
    db.refresh(policy)

    after = serialize_asset_risk_policy(policy)
    affected_agent_ids = agent_ids_matching_risk_tags(
        db,
        {previous_target_tag, str(policy.target_tag or "").strip().lower()},
    )
    snapshot = (
        capture_asset_risk_snapshots(
            db,
            source=f"risk_policy_updated:{principal['actor']}",
            minimum_interval_seconds=0,
            agent_ids=affected_agent_ids,
        )
        if affected_agent_ids
        else {"created": 0, "skipped": 0, "pruned": 0}
    )
    audit(
        db,
        principal["actor"],
        "asset_risk.policy.updated",
        "asset_risk_policy",
        policy.id,
        {"before": before, "after": after, "affected_agents": len(affected_agent_ids), "snapshot": snapshot},
    )
    return {"ok": True, "policy": after}


@app.get("/api/admin/agents/{agent_id}/risk-profile")
def get_asset_risk_profile(
    agent_id: str,
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    return {
        "agent_id": agent.id,
        "hostname": agent.hostname,
        "profile": serialize_asset_risk_profile(agent.risk_profile),
        "effective": {
            "criticality": asset_criticality(agent),
            "exposure": asset_exposure(agent),
            "compensating": asset_compensating_factor(agent),
        },
    }


@app.put("/api/admin/agents/{agent_id}/risk-profile")
def update_asset_risk_profile(
    agent_id: str,
    body: AssetRiskProfileUpdate,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")

    allowed_controls = {"segmented", "edr-protected", "restricted-egress"}
    controls = body.compensating_controls
    normalized_controls = None
    if controls is not None:
        normalized_controls = sorted({
            str(value).strip().lower()
            for value in controls
            if str(value).strip()
        })
        invalid = [value for value in normalized_controls if value not in allowed_controls]
        if invalid:
            raise HTTPException(
                status_code=400,
                detail={"message": "unsupported compensating control", "controls": invalid},
            )

    profile = agent.risk_profile
    if not profile:
        profile = AssetRiskProfile(agent=agent)
        db.add(profile)

    before = serialize_asset_risk_profile(profile)
    profile.criticality_override = body.criticality
    profile.external_override = body.external
    profile.controls_json = (
        dump(normalized_controls)
        if normalized_controls is not None
        else None
    )
    profile.owner = (body.owner or "").strip()
    profile.business_service = (body.business_service or "").strip()
    profile.environment = (body.environment or "").strip().lower()
    reason = body.reason.strip()
    if len(reason) < 5:
        raise HTTPException(status_code=400, detail="risk profile reason must contain at least 5 non-space characters")
    profile.reason = reason
    profile.updated_by = principal["actor"]
    profile.updated_at = now()
    db.commit()
    db.refresh(profile)

    capture_asset_risk_snapshots(
        db,
        source=f"risk_profile:{principal['actor']}",
        minimum_interval_seconds=0,
        agent_ids={agent.id},
    )
    result = serialize_asset_risk_profile(profile)
    audit(
        db,
        principal["actor"],
        "asset_risk.profile.updated",
        "agent",
        agent.id,
        {
            "before": before,
            "after": result,
            "effective": {
                "criticality": asset_criticality(agent),
                "exposure": asset_exposure(agent),
                "compensating": asset_compensating_factor(agent),
            },
        },
    )
    return {
        "ok": True,
        "profile": result,
        "effective": {
            "criticality": asset_criticality(agent),
            "exposure": asset_exposure(agent),
            "compensating": asset_compensating_factor(agent),
        },
    }


@app.get("/api/admin/agents")
def list_agents(_=Depends(require_viewer), db: Session = Depends(get_db)):
    return [serialize_agent(a) for a in db.query(Agent).order_by(Agent.hostname.asc()).all()]


@app.post("/api/admin/agents/{agent_id}/updates/quarantine/clear")
def clear_agent_update_quarantine(
    agent_id: str,
    body: AgentUpdateQuarantineClearRequest,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    if not body.acknowledge_risk:
        raise HTTPException(
            status_code=400,
            detail="explicit quarantine clear risk acknowledgement is required",
        )

    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    if str(agent.os_family or "").lower() != "linux":
        raise HTTPException(status_code=409, detail="agent update quarantine applies only to Linux activation")

    inventory = load(agent.inventory_json, {})
    update_state = inventory.get("update") if isinstance(inventory.get("update"), dict) else {}
    activation_state = inventory.get("activation") if isinstance(inventory.get("activation"), dict) else {}
    runtime = agent_runtime_metadata(agent)

    if update_state.get("status") != "quarantined":
        raise HTTPException(status_code=409, detail="agent does not report a quarantined release")
    if str(update_state.get("quarantined_version") or update_state.get("staged_version") or "") != body.expected_version:
        raise HTTPException(status_code=409, detail="quarantined release does not match requested version")
    if activation_state.get("status") != "rolled_back":
        raise HTTPException(status_code=409, detail="agent activation did not report a watchdog rollback")
    if str(activation_state.get("target_version") or "") != body.expected_version:
        raise HTTPException(status_code=409, detail="rollback target does not match quarantined release")
    if "signed_update_quarantine_v1" not in set(runtime.get("capabilities") or []):
        raise HTTPException(status_code=409, detail="agent does not support quarantine clearing")

    active_execution = db.query(PatchJob).filter(
        PatchJob.agent_id == agent.id,
        PatchJob.status.in_(["claimed", "running", "stalled"]),
    ).first()
    if active_execution:
        raise HTTPException(
            status_code=409,
            detail=f"agent has active execution {active_execution.id} in status {active_execution.status}",
        )

    existing = db.query(PatchJob).filter(
        PatchJob.agent_id == agent.id,
        PatchJob.action.in_(["activate_agent_update", "clear_agent_update_quarantine"]),
        PatchJob.status.in_(["pending", "blocked", "claimed", "running", "stalled"]),
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="agent already has an unfinished update lifecycle job")

    payload = {
        "expected_version": body.expected_version,
        "approved_reason": body.reason,
        "approved_by": principal["actor"],
    }
    campaign = Campaign(
        id=str(uuid.uuid4()),
        name=f"Release quarantine clear {agent.hostname} v{body.expected_version}",
        description=body.reason,
        target_os="linux",
        target_tag="",
        ring_percent=100,
        action="clear_agent_update_quarantine",
        payload_json=dump(payload),
        allow_reboot=False,
        status="deployed",
    )
    job = PatchJob(
        id=str(uuid.uuid4()),
        campaign=campaign,
        agent=agent,
        action="clear_agent_update_quarantine",
        payload_json=dump(payload),
        status="pending",
    )
    db.add_all([campaign, job])
    db.commit()

    audit(
        db,
        principal["actor"],
        "agent.update.quarantine.clear.approved",
        "job",
        job.id,
        {
            "agent_id": agent.id,
            "hostname": agent.hostname,
            "version": body.expected_version,
            "rollback_reason": activation_state.get("rollback_reason", ""),
            "reason": body.reason,
        },
    )
    return {"ok": True, "job": serialize_job(job), "campaign": serialize_campaign(campaign)}


@app.post("/api/admin/agents/{agent_id}/updates/activate")
def approve_agent_update_activation(
    agent_id: str,
    body: AgentUpdateActivationRequest,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    if not body.acknowledge_risk:
        raise HTTPException(
            status_code=400,
            detail="explicit agent update activation risk acknowledgement is required",
        )

    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    if str(agent.os_family or "").lower() != "linux":
        raise HTTPException(
            status_code=409,
            detail="automatic agent activation is supported only on Linux",
        )
    if not agent_heartbeat_fresh(agent):
        raise HTTPException(
            status_code=409,
            detail="agent heartbeat is too old for update activation approval",
        )

    release_binding = signed_release_binding(body.expected_version)
    binding_ok, binding_reason = staged_release_binding_matches(agent, release_binding)
    if not binding_ok:
        raise HTTPException(
            status_code=409,
            detail=f"staged release does not match published signed release: {binding_reason}",
        )

    inventory = load(agent.inventory_json, {})
    update_state = inventory.get("update") if isinstance(inventory.get("update"), dict) else {}
    activation_state = inventory.get("activation") if isinstance(inventory.get("activation"), dict) else {}
    runtime = agent_runtime_metadata(agent)

    if update_state.get("status") != "staged":
        raise HTTPException(status_code=409, detail="agent does not report a staged update")
    if str(update_state.get("staged_version") or "") != body.expected_version:
        raise HTTPException(status_code=409, detail="staged agent version does not match approval")
    if "signed_update_activation_v1" not in set(runtime.get("capabilities") or []):
        raise HTTPException(status_code=409, detail="agent does not support signed update activation")
    if activation_state.get("status") in {"switching", "pending"}:
        raise HTTPException(status_code=409, detail="agent update activation is already pending")
    if activation_state.get("status") == "rolled_back":
        raise HTTPException(
            status_code=409,
            detail="rolled-back release is quarantined and must be explicitly cleared first",
        )

    active_execution = db.query(PatchJob).filter(
        PatchJob.agent_id == agent.id,
        PatchJob.status.in_(["claimed", "running", "stalled"]),
    ).first()
    if active_execution:
        raise HTTPException(
            status_code=409,
            detail=f"agent has active execution {active_execution.id} in status {active_execution.status}",
        )

    existing_update = db.query(PatchJob).filter(
        PatchJob.agent_id == agent.id,
        PatchJob.action == "activate_agent_update",
        PatchJob.status.in_(["pending", "blocked", "claimed", "running", "stalled"]),
    ).first()
    if existing_update:
        raise HTTPException(
            status_code=409,
            detail="agent already has an unfinished update activation job",
        )

    approved_at = now()
    approval_expires_at = approved_at + timedelta(seconds=AGENT_UPDATE_APPROVAL_TTL_SECONDS)
    payload = {
        "expected_version": body.expected_version,
        "approved_reason": body.reason,
        "approved_by": principal["actor"],
        "activation_platform": "linux",
        "approved_at": approved_at.isoformat(),
        "approval_expires_at": approval_expires_at.isoformat(),
        "release_binding": release_binding,
    }

    campaign = Campaign(
        id=str(uuid.uuid4()),
        name=f"Agent update {agent.hostname} -> v{body.expected_version}",
        description=body.reason,
        target_os="linux",
        target_tag="",
        ring_percent=100,
        action="activate_agent_update",
        payload_json=dump(payload),
        allow_reboot=False,
        status="deployed",
    )
    job = PatchJob(
        id=str(uuid.uuid4()),
        campaign=campaign,
        agent=agent,
        action="activate_agent_update",
        payload_json=dump(payload),
        status="pending",
    )
    db.add_all([campaign, job])
    db.commit()

    audit(
        db,
        principal["actor"],
        "agent.update.activation.approved",
        "job",
        job.id,
        {
            "agent_id": agent.id,
            "hostname": agent.hostname,
            "from_version": runtime.get("version", ""),
            "to_version": body.expected_version,
            "reason": body.reason,
            "approval_expires_at": approval_expires_at.isoformat(),
            "release_binding": release_binding,
        },
    )

    return {
        "ok": True,
        "campaign": serialize_campaign(campaign),
        "job": serialize_job(job),
    }


@app.put("/api/admin/agents/{agent_id}/mtls")
def bind_agent_mtls(
    agent_id: str,
    body: AgentMtlsBindRequest,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")

    fingerprint = normalize_client_cert_fingerprint(body.fingerprint)
    if not fingerprint:
        raise HTTPException(status_code=400, detail="client certificate fingerprint is required")

    existing = db.query(Agent).filter(
        Agent.client_cert_fingerprint == fingerprint,
        Agent.id != agent.id,
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="client certificate is already bound to another agent")

    previous = agent.client_cert_fingerprint or ""
    agent.client_cert_fingerprint = fingerprint
    db.commit()

    audit(
        db,
        principal["actor"],
        "agent.mtls.bound",
        "agent",
        agent.id,
        {
            "hostname": agent.hostname,
            "previous_fingerprint": previous,
            "fingerprint": fingerprint,
            "reason": body.reason,
        },
    )
    return serialize_agent(agent)


@app.put("/api/admin/agents/{agent_id}/tags")
def update_tags(agent_id: str, body: TagUpdate, principal=Depends(require_operator), db: Session = Depends(get_db)):
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    agent.tags = dump(sorted(set(body.tags)))
    db.commit()
    audit(db, principal["actor"], "agent.tags.updated", "agent", agent_id, {"tags": body.tags})
    return serialize_agent(agent)


@app.get("/api/admin/integrations/greenbone")
def greenbone_status(_=Depends(require_viewer), db: Session = Depends(get_db)):
    config = public_greenbone_config()
    state = integration_state(db, "greenbone")
    state.enabled = config["enabled"]
    db.commit()
    return serialize_integration_state(state, config)


@app.post("/api/admin/integrations/greenbone/sync")
def greenbone_sync_now(principal=Depends(require_operator), db: Session = Depends(get_db)):
    config = public_greenbone_config()
    if not config["configured"]:
        raise HTTPException(status_code=409, detail="Greenbone integration is not fully configured")
    try:
        result = run_greenbone_sync()
        audit(db, principal["actor"], "greenbone.sync.requested", "integration", "greenbone", result)
        return {"ok": True, "result": result}
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/admin/integrations/threat-intel")
def threat_intel_status(_=Depends(require_viewer), db: Session = Depends(get_db)):
    config = public_threat_intel_config()
    state = integration_state(db, "threat_intel")
    state.enabled = config["enabled"]
    db.commit()
    return serialize_integration_state(state, config)


@app.post("/api/admin/integrations/threat-intel/sync")
def threat_intel_sync_now(principal=Depends(require_operator), db: Session = Depends(get_db)):
    config = public_threat_intel_config()
    if not config["configured"]:
        raise HTTPException(status_code=409, detail="threat intel integration is not configured")
    try:
        result = run_threat_intel_sync()
        audit(
            db,
            principal["actor"],
            "threat_intel.sync.requested",
            "integration",
            "threat_intel",
            result,
        )
        return {"ok": True, "result": result}
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/admin/vulnerabilities")
def list_vulnerabilities(
    status: str | None = None,
    severity: str | None = None,
    agent_id: str | None = None,
    limit: int = 1000,
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    q = db.query(VulnerabilityFinding).options(
        selectinload(VulnerabilityFinding.agent),
        selectinload(VulnerabilityFinding.sla_exceptions),
        selectinload(VulnerabilityFinding.remediation_evidence).selectinload(RemediationEvidence.campaign),
        selectinload(VulnerabilityFinding.remediation_evidence).selectinload(RemediationEvidence.agent),
    ).order_by(
        VulnerabilityFinding.last_seen.desc(),
    )
    if status:
        q = q.filter(VulnerabilityFinding.status == status.lower())
    if severity:
        q = q.filter(VulnerabilityFinding.severity == severity.lower())
    if agent_id:
        q = q.filter(VulnerabilityFinding.agent_id == agent_id)
    # Risk is calculated from scanner + threat-intel context in Python.
    # Apply the response limit only after risk ordering so an older urgent
    # finding cannot be hidden by a recency-first SQL LIMIT.
    items = [serialize_vulnerability(item) for item in q.all()]
    items.sort(key=lambda item: (
        item["status"] != "open",
        -(item.get("risk") or {}).get("score", 0),
        -float(item.get("cvss") or 0),
        -(datetime.fromisoformat(item["last_seen"]).timestamp() if item.get("last_seen") else 0),
    ))
    return items[:max(1, min(limit, 5000))]


@app.post("/api/admin/vulnerabilities/import")
def import_vulnerabilities(
    body: VulnerabilityImportRequest,
    principal=Depends(require_operator),
    db: Session = Depends(get_db),
):
    source = body.source.strip().lower()
    if not re.fullmatch(r"[a-z0-9._-]{1,64}", source):
        raise HTTPException(status_code=400, detail="invalid vulnerability source")

    stats = upsert_vulnerability_findings(db, source, body.scan_id, body.findings)
    capture_remediation_project_snapshots(db, source=f"vulnerability_import:{source}")
    audit(
        db,
        principal["actor"],
        "vulnerabilities.imported",
        "vulnerability_source",
        source,
        {
            "scan_id": body.scan_id,
            "received": len(body.findings),
            "normalized": stats["normalized"],
            "created": stats["created"],
            "updated": stats["updated"],
            "matched": stats["matched"],
        },
    )
    return {
        "ok": True,
        "source": source,
        "scan_id": body.scan_id,
        "received": len(body.findings),
        "normalized": stats["normalized"],
        "created": stats["created"],
        "updated": stats["updated"],
        "matched": stats["matched"],
    }


@app.get("/api/admin/vulnerabilities/{finding_id}/sla-exceptions")
def list_vulnerability_sla_exceptions(
    finding_id: str,
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    finding = db.get(VulnerabilityFinding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="vulnerability finding not found")
    items = sorted(
        list(finding.sla_exceptions or []),
        key=lambda item: item.created_at or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return [serialize_sla_exception(item) for item in items]


@app.post("/api/admin/vulnerabilities/{finding_id}/sla-exceptions")
def create_vulnerability_sla_exception(
    finding_id: str,
    body: VulnerabilitySlaExceptionCreate,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    finding = db.query(VulnerabilityFinding).filter(
        VulnerabilityFinding.id == finding_id
    ).with_for_update().first()
    if not finding:
        raise HTTPException(status_code=404, detail="vulnerability finding not found")
    if finding.status != "open":
        raise HTTPException(status_code=409, detail="SLA exception requires an open vulnerability")

    reason = body.reason.strip()
    if len(reason) < 5:
        raise HTTPException(status_code=400, detail="SLA exception reason must contain at least 5 non-space characters")

    current = now()
    expires_at = body.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= current:
        raise HTTPException(status_code=400, detail="SLA exception expiry must be in the future")
    if expires_at > current + timedelta(days=365):
        raise HTTPException(status_code=400, detail="SLA exception cannot exceed 365 days")
    if active_sla_exception(finding, current):
        raise HTTPException(status_code=409, detail="an active SLA exception already exists")

    item = VulnerabilitySlaException(
        id=str(uuid.uuid4()),
        finding=finding,
        reason=reason,
        approved_by=principal["actor"],
        expires_at=expires_at,
    )
    db.add(item)
    db.commit()
    audit(
        db,
        principal["actor"],
        "vulnerability.sla_exception.created",
        "vulnerability",
        finding.id,
        {
            "exception_id": item.id,
            "cve": finding.cve,
            "expires_at": expires_at.isoformat(),
            "reason": item.reason,
        },
    )
    return serialize_sla_exception(item)


@app.post("/api/admin/vulnerabilities/{finding_id}/sla-exceptions/{exception_id}/revoke")
def revoke_vulnerability_sla_exception(
    finding_id: str,
    exception_id: str,
    body: VulnerabilitySlaExceptionRevoke,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    item = db.get(VulnerabilitySlaException, exception_id)
    if not item or item.finding_id != finding_id:
        raise HTTPException(status_code=404, detail="SLA exception not found")
    if item.revoked_at is not None:
        raise HTTPException(status_code=409, detail="SLA exception is already revoked")

    revoke_reason = body.reason.strip()
    if len(revoke_reason) < 5:
        raise HTTPException(status_code=400, detail="SLA exception revoke reason must contain at least 5 non-space characters")

    item.revoked_at = now()
    item.revoked_by = principal["actor"]
    item.revoke_reason = revoke_reason
    db.commit()
    audit(
        db,
        principal["actor"],
        "vulnerability.sla_exception.revoked",
        "vulnerability",
        finding_id,
        {
            "exception_id": item.id,
            "reason": item.revoke_reason,
        },
    )
    return serialize_sla_exception(item)


@app.put("/api/admin/vulnerabilities/{finding_id}/status")
def update_vulnerability_status(
    finding_id: str,
    body: VulnerabilityStatusUpdate,
    principal=Depends(require_operator),
    db: Session = Depends(get_db),
):
    allowed = {"open", "not_detected", "remediated", "accepted_risk", "false_positive"}
    status = body.status.strip().lower()
    if status not in allowed:
        raise HTTPException(status_code=400, detail="invalid vulnerability status")

    finding = db.get(VulnerabilityFinding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="vulnerability finding not found")

    finding.status = status
    finding.resolved_at = now() if status == "remediated" else None
    db.commit()
    capture_remediation_project_snapshots(
        db,
        source=f"vulnerability_status:{principal['actor']}",
        minimum_interval_seconds=0,
    )
    audit(
        db,
        principal["actor"],
        "vulnerability.status.updated",
        "vulnerability",
        finding.id,
        {"status": status, "cve": finding.cve, "source": finding.source},
    )
    return serialize_vulnerability(finding)



@app.get("/api/admin/remediation-evidence")
def list_remediation_evidence(
    status: str | None = None,
    finding_id: str | None = None,
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    q = db.query(RemediationEvidence).order_by(RemediationEvidence.created_at.desc())
    if status:
        q = q.filter(RemediationEvidence.status == status.strip().lower())
    if finding_id:
        q = q.filter(RemediationEvidence.finding_id == finding_id)
    return [serialize_remediation_evidence(item) for item in q.limit(1000).all()]


@app.post("/api/admin/remediation-evidence/{evidence_id}/rescan")
def retry_remediation_rescan(
    evidence_id: str,
    body: RemediationRescanRequest,
    principal=Depends(require_operator),
    db: Session = Depends(get_db),
):
    item = db.get(RemediationEvidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="remediation evidence not found")
    if item.status not in {"error", "still_detected"}:
        raise HTTPException(
            status_code=409,
            detail="manual rescan is allowed only after an error or a still-detected result",
        )

    validation = job_post_patch_validation(item.job)
    if validation.get("status") != "passed":
        raise HTTPException(
            status_code=409,
            detail={"message": "post-patch validation is not healthy", "validation": validation},
        )

    previous_status = item.status
    evidence = load(item.evidence_json, {})
    retries = evidence.get("manual_rescans")
    if not isinstance(retries, list):
        retries = []
    retries.append({
        "requested_by": principal["actor"],
        "reason": body.reason,
        "time": now().isoformat(),
        "previous_status": previous_status,
    })
    evidence["manual_rescans"] = retries[-20:]
    item.evidence_json = dump(evidence)
    db.commit()

    if not start_remediation_rescan(db, item, principal["actor"]):
        db.refresh(item)
        raise HTTPException(
            status_code=409,
            detail=item.error or "rescan could not be started now",
        )

    audit(
        db,
        principal["actor"],
        "remediation.rescan.manual",
        "remediation_evidence",
        item.id,
        {
            "reason": body.reason,
            "previous_status": previous_status,
            "report_id": item.rescan_report_id,
        },
    )
    return serialize_remediation_evidence(item)


@app.get("/api/admin/campaigns")
def list_campaigns(_=Depends(require_viewer), db: Session = Depends(get_db)):
    campaigns = db.query(Campaign).order_by(Campaign.created_at.desc()).all()
    return [serialize_campaign(c) for c in campaigns]


def agent_update_rollout_eligibility(
    db: Session,
    agent: Agent,
    expected_version: str,
    target_tag: str = "",
    release_binding: dict | None = None,
) -> tuple[bool, str]:
    if str(agent.os_family or "").lower() != "linux":
        return False, "not_linux"
    if not agent_heartbeat_fresh(agent):
        return False, "stale_heartbeat"

    tags = load(agent.tags, [])
    if target_tag and target_tag not in tags:
        return False, "tag_mismatch"

    runtime = agent_runtime_metadata(agent)
    if "signed_update_activation_v1" not in set(runtime.get("capabilities") or []):
        return False, "activation_capability_missing"

    current_version = str(runtime.get("version") or "")
    if not current_version or not version_at_least(expected_version, current_version) or expected_version == current_version:
        return False, "version_not_upgrade"

    inventory = load(agent.inventory_json, {})
    update_state = inventory.get("update") if isinstance(inventory.get("update"), dict) else {}
    activation_state = inventory.get("activation") if isinstance(inventory.get("activation"), dict) else {}

    if update_state.get("status") != "staged":
        return False, "not_staged"
    if str(update_state.get("staged_version") or "") != expected_version:
        return False, "staged_version_mismatch"
    if release_binding:
        binding_ok, binding_reason = staged_release_binding_matches(agent, release_binding)
        if not binding_ok:
            return False, binding_reason
    if activation_state.get("status") in {"switching", "pending", "rolled_back"}:
        return False, "activation_not_eligible"

    busy = db.query(PatchJob).filter(
        PatchJob.agent_id == agent.id,
        PatchJob.status.in_(["claimed", "running", "stalled"]),
    ).first()
    if busy:
        return False, "active_execution"

    return True, "eligible"


@app.post("/api/admin/agent-update-rollouts/preview")
def preview_agent_update_rollout(
    body: AgentUpdateRolloutCreate,
    _=Depends(require_admin),
    db: Session = Depends(get_db),
):
    if body.ring_percent not in {10, 30, 100}:
        raise HTTPException(status_code=400, detail="agent update ring must be 10, 30 or 100")

    release_binding = signed_release_binding(body.expected_version)
    eligible = []
    skipped = {}
    details = []

    for agent in db.query(Agent).order_by(Agent.id.asc()).all():
        ok, reason = agent_update_rollout_eligibility(
            db,
            agent,
            body.expected_version,
            body.target_tag.strip(),
            release_binding,
        )
        if ok:
            eligible.append(agent)
        else:
            skipped[reason] = skipped.get(reason, 0) + 1
        details.append({
            "agent_id": agent.id,
            "hostname": agent.hostname,
            "eligible": ok,
            "reason": reason,
            "runtime_version": agent_runtime_metadata(agent).get("version", ""),
            "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
        })

    ordered = sorted(eligible, key=lambda agent: ring_bucket(agent.id))
    selected_count = (
        max(1, math.ceil(len(ordered) * body.ring_percent / 100))
        if ordered
        else 0
    )
    selected_ids = {agent.id for agent in ordered[:selected_count]}
    for item in details:
        item["selected"] = bool(item["agent_id"] in selected_ids)

    return {
        "ok": True,
        "expected_version": body.expected_version,
        "ring_percent": body.ring_percent,
        "target_tag": body.target_tag.strip(),
        "release_binding": release_binding,
        "approval_ttl_seconds": AGENT_UPDATE_APPROVAL_TTL_SECONDS,
        "max_heartbeat_age_seconds": AGENT_UPDATE_MAX_HEARTBEAT_AGE_SECONDS,
        "eligible_agents": len(eligible),
        "selected_agents": selected_count,
        "skipped": skipped,
        "agents": details[:200],
    }


@app.post("/api/admin/agent-update-rollouts")
def create_agent_update_rollout(
    body: AgentUpdateRolloutCreate,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    if not body.acknowledge_risk:
        raise HTTPException(
            status_code=400,
            detail="explicit agent update rollout risk acknowledgement is required",
        )
    if body.ring_percent not in {10, 30, 100}:
        raise HTTPException(status_code=400, detail="agent update ring must be 10, 30 or 100")

    release_binding = signed_release_binding(body.expected_version)
    eligible = []
    skipped = {}
    for agent in db.query(Agent).order_by(Agent.id.asc()).all():
        ok, reason = agent_update_rollout_eligibility(
            db,
            agent,
            body.expected_version,
            body.target_tag.strip(),
            release_binding,
        )
        if ok:
            eligible.append(agent)
        else:
            skipped[reason] = skipped.get(reason, 0) + 1

    if not eligible:
        raise HTTPException(
            status_code=409,
            detail={"message": "no eligible staged Linux agents matched rollout", "skipped": skipped},
        )

    snapshot_ids = sorted(agent.id for agent in eligible)
    approved_at = now()
    approval_expires_at = approved_at + timedelta(seconds=AGENT_UPDATE_APPROVAL_TTL_SECONDS)
    payload = {
        "rollout_type": "agent_update",
        "expected_version": body.expected_version,
        "approved_reason": body.reason,
        "approved_by": principal["actor"],
        "approved_at": approved_at.isoformat(),
        "approval_expires_at": approval_expires_at.isoformat(),
        "release_binding": release_binding,
        "target_agent_ids": snapshot_ids,
        "post_patch_validation": True,
        "health_gate_override_allowed": False,
        "prepare_rollback": False,
        "rollback_required": False,
        "reboot_policy": "never",
        "maintenance_start": "",
        "maintenance_end": "",
        "maintenance_timezone": "UTC",
        "maintenance_days": list(range(7)),
    }

    campaign = Campaign(
        id=str(uuid.uuid4()),
        name=body.name,
        description=body.description or body.reason,
        target_os="linux",
        target_tag=body.target_tag.strip(),
        ring_percent=body.ring_percent,
        action="activate_agent_update",
        payload_json=dump(payload),
        allow_reboot=False,
        status="deployed",
    )
    db.add(campaign)
    db.flush()

    selected = agents_for_ring(db, campaign, body.ring_percent)
    jobs = add_ring_jobs(db, campaign, selected, body.ring_percent)
    db.commit()

    audit(
        db,
        principal["actor"],
        "agent.update.rollout.created",
        "campaign",
        campaign.id,
        {
            "expected_version": body.expected_version,
            "ring_percent": body.ring_percent,
            "eligible_agents": len(snapshot_ids),
            "initial_agents": len(jobs),
            "target_tag": body.target_tag.strip(),
            "skipped": skipped,
            "reason": body.reason,
            "approval_expires_at": approval_expires_at.isoformat(),
            "release_binding": release_binding,
        },
    )

    return {
        "ok": True,
        "eligible_agents": len(snapshot_ids),
        "initial_agents": len(jobs),
        "skipped": skipped,
        "campaign": serialize_campaign(campaign),
    }




@app.post("/api/admin/campaigns/{campaign_id}/approval/approve")
def approve_campaign(
    campaign_id: str,
    body: CampaignApprovalDecision,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    campaign = db.get(Campaign, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="campaign not found")
    approval = campaign.approval
    if not approval or not serialize_campaign_approval(campaign)["required"]:
        raise HTTPException(status_code=409, detail="campaign does not require approval")
    if campaign.status != "draft":
        raise HTTPException(status_code=409, detail="only draft campaigns can be approved")
    if approval.status != "pending":
        raise HTTPException(status_code=409, detail=f"campaign approval is {approval.status}")
    if approval.requested_by == principal["actor"]:
        raise HTTPException(status_code=409, detail="requester cannot approve their own campaign")

    approval.status = "approved"
    approval.decided_by = principal["actor"]
    approval.decision_reason = body.reason.strip()
    approval.decided_at = now()
    db.commit()
    audit(
        db,
        principal["actor"],
        "campaign.approval.approved",
        "campaign",
        campaign.id,
        serialize_campaign_approval(campaign),
    )
    return {"ok": True, "campaign": serialize_campaign(campaign)}


@app.post("/api/admin/campaigns/{campaign_id}/approval/reject")
def reject_campaign(
    campaign_id: str,
    body: CampaignApprovalDecision,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    campaign = db.get(Campaign, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="campaign not found")
    approval = campaign.approval
    if not approval or not serialize_campaign_approval(campaign)["required"]:
        raise HTTPException(status_code=409, detail="campaign does not require approval")
    if campaign.status != "draft":
        raise HTTPException(status_code=409, detail="only draft campaigns can be rejected")
    if approval.status != "pending":
        raise HTTPException(status_code=409, detail=f"campaign approval is {approval.status}")

    approval.status = "rejected"
    approval.decided_by = principal["actor"]
    approval.decision_reason = body.reason.strip()
    approval.decided_at = now()
    db.commit()
    audit(
        db,
        principal["actor"],
        "campaign.approval.rejected",
        "campaign",
        campaign.id,
        serialize_campaign_approval(campaign),
    )
    return {"ok": True, "campaign": serialize_campaign(campaign)}


@app.get("/api/admin/patch-block-rules")
def list_patch_block_rules(_=Depends(require_viewer), db: Session = Depends(get_db)):
    reference = now()
    rules = db.query(PatchBlockRule).order_by(
        PatchBlockRule.enabled.desc(),
        PatchBlockRule.patch_ref.asc(),
        PatchBlockRule.name.asc(),
    ).all()
    return {
        "generated_at": reference.isoformat(),
        "items": [serialize_patch_block_rule(rule, reference) for rule in rules],
        "summary": {
            "total": len(rules),
            "active": sum(1 for rule in rules if serialize_patch_block_rule(rule, reference)["active"]),
            "disabled": sum(1 for rule in rules if not rule.enabled),
            "expired": sum(1 for rule in rules if serialize_patch_block_rule(rule, reference)["expired"]),
        },
    }


@app.post("/api/admin/patch-block-rules")
def create_patch_block_rule(
    body: PatchBlockRuleCreate,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    name = body.name.strip()
    patch_ref = body.patch_ref.strip()
    target_os = body.target_os.strip().lower() or "all"
    target_tag = body.target_tag.strip()
    reason = body.reason.strip()
    if target_os not in {"all", "windows", "linux", "macos"}:
        raise HTTPException(status_code=400, detail="target_os must be all, windows, linux or macos")
    if db.query(PatchBlockRule).filter(func.lower(PatchBlockRule.name) == name.lower()).first():
        raise HTTPException(status_code=409, detail="patch block rule name already exists")
    expires_at = body.expires_at
    if expires_at is not None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now():
            raise HTTPException(status_code=400, detail="expires_at must be in the future")

    rule = PatchBlockRule(
        id=str(uuid.uuid4()),
        name=name,
        patch_ref=patch_ref,
        target_os=target_os,
        target_tag=target_tag,
        reason=reason,
        enabled=True,
        expires_at=expires_at,
        created_by=principal["actor"],
        updated_by=principal["actor"],
    )
    db.add(rule)
    db.commit()
    audit(
        db,
        principal["actor"],
        "patch_block_rule.created",
        "patch_block_rule",
        rule.id,
        serialize_patch_block_rule(rule),
    )
    return {"ok": True, "rule": serialize_patch_block_rule(rule)}


@app.patch("/api/admin/patch-block-rules/{rule_id}")
def update_patch_block_rule(
    rule_id: str,
    body: PatchBlockRuleUpdate,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    rule = db.get(PatchBlockRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="patch block rule not found")
    before = serialize_patch_block_rule(rule)
    rule.enabled = bool(body.enabled)
    rule.reason = body.reason.strip()
    rule.updated_by = principal["actor"]
    db.commit()
    after = serialize_patch_block_rule(rule)
    audit(
        db,
        principal["actor"],
        "patch_block_rule.updated",
        "patch_block_rule",
        rule.id,
        {"before": before, "after": after},
    )
    return {"ok": True, "rule": after}


@app.post("/api/admin/campaigns")
def default_rollout_plan(ring_percent: int) -> list[int]:
    ring = max(1, min(int(ring_percent), 100))
    if ring >= 100:
        return [100]
    legacy_steps = [5, 10, 30, 100]
    plan = [ring]
    plan.extend(step for step in legacy_steps if step > ring)
    return sorted(set(plan))


def create_campaign(body: CampaignCreate, principal=Depends(require_operator), db: Session = Depends(get_db)):
    if body.action not in {"scan_updates", "install_updates"}:
        raise HTTPException(status_code=400, detail="unsupported action")

    validate_campaign_policy(body)

    target_agent = None
    if body.target_agent_id:
        target_agent = db.get(Agent, body.target_agent_id)
        if not target_agent:
            raise HTTPException(status_code=404, detail="target agent not found")

    target_agent_ids = list(dict.fromkeys(
        str(agent_id).strip()
        for agent_id in body.target_agent_ids
        if str(agent_id).strip()
    ))
    if body.target_agent_id and target_agent_ids:
        raise HTTPException(
            status_code=400,
            detail="use target_agent_id or target_agent_ids, not both",
        )
    target_agents = []
    if target_agent_ids:
        target_agents = db.query(Agent).filter(Agent.id.in_(target_agent_ids)).all()
        found_ids = {agent.id for agent in target_agents}
        missing_ids = [agent_id for agent_id in target_agent_ids if agent_id not in found_ids]
        if missing_ids:
            raise HTTPException(
                status_code=404,
                detail={"message": "one or more target agents were not found", "agent_ids": missing_ids[:20]},
            )
        if len(target_agents) != len(target_agent_ids):
            raise HTTPException(status_code=409, detail="target agent snapshot could not be resolved")

    target_finding = None
    if body.target_finding_id:
        target_finding = db.get(VulnerabilityFinding, body.target_finding_id)
        if not target_finding:
            raise HTTPException(status_code=404, detail="source vulnerability finding not found")
        if target_agent and target_finding.agent_id and target_finding.agent_id != target_agent.id:
            raise HTTPException(status_code=400, detail="vulnerability finding does not belong to target agent")
        if len(target_agent_ids) > 1:
            raise HTTPException(
                status_code=400,
                detail="a single source finding cannot be attached to a multi-asset campaign",
            )
        if target_agent_ids and target_finding.agent_id and target_finding.agent_id not in set(target_agent_ids):
            raise HTTPException(status_code=400, detail="vulnerability finding does not belong to campaign target snapshot")

    if body.rollback_required and not body.prepare_rollback:
        raise HTTPException(status_code=400, detail="rollback_required requires prepare_rollback")
    approval_reason = body.approval_reason.strip()
    if body.approval_required and len(approval_reason) < 5:
        raise HTTPException(status_code=400, detail="approval_reason is required when approval_required is true")

    rollout_plan = []
    for value in body.rollout_plan:
        percent = int(value)
        if percent < 1 or percent > 100:
            raise HTTPException(status_code=400, detail="rollout_plan values must be between 1 and 100")
        if percent not in rollout_plan:
            rollout_plan.append(percent)
    rollout_plan = sorted(rollout_plan)
    if rollout_plan:
        if body.ring_percent not in rollout_plan:
            rollout_plan.append(body.ring_percent)
            rollout_plan = sorted(set(rollout_plan))
        if rollout_plan[0] != body.ring_percent:
            raise HTTPException(status_code=400, detail="rollout_plan must start at campaign ring_percent")
        if rollout_plan[-1] != 100:
            raise HTTPException(status_code=400, detail="rollout_plan must end at 100")
    else:
        rollout_plan = default_rollout_plan(body.ring_percent)

    reboot_policy = body.reboot_policy
    if body.allow_reboot and reboot_policy == "never":
        reboot_policy = "if_required"
    allow_reboot = reboot_policy == "if_required"

    policy_payload = {
        **body.payload,
        "allow_reboot": allow_reboot,
        "reboot_policy": reboot_policy,
        "maintenance_start": body.maintenance_start.strip(),
        "maintenance_end": body.maintenance_end.strip(),
        "maintenance_timezone": body.maintenance_timezone,
        "maintenance_days": body.maintenance_days,
        "post_patch_validation": body.post_patch_validation,
        "health_policy": health_policy_from_campaign(body),
        "prepare_rollback": body.prepare_rollback,
        "rollback_required": body.rollback_required,
        "target_agent_id": target_agent.id if target_agent else "",
        "target_agent_hostname": target_agent.hostname if target_agent else "",
        "target_agent_ids": target_agent_ids,
        "target_agent_count": len(target_agent_ids),
        "source_finding_id": target_finding.id if target_finding else "",
        "source_cve": target_finding.cve if target_finding else "",
        "approval_required": body.approval_required,
        "approval_reason": approval_reason if body.approval_required else "",
        "rollout_governance": {
            "plan": rollout_plan,
            "soak_minutes": int(body.soak_minutes),
            "promotion_min_success_rate": float(body.promotion_min_success_rate),
            "promotion_max_success_drop": float(body.promotion_max_success_drop),
            "pause_on_failure": bool(body.pause_on_failure),
        },
    }

    campaign = Campaign(
        id=str(uuid.uuid4()),
        name=body.name,
        description=body.description,
        target_os=body.target_os.lower(),
        target_tag=body.target_tag,
        ring_percent=body.ring_percent,
        action=body.action,
        payload_json=dump(policy_payload),
        not_before=body.not_before,
        allow_reboot=allow_reboot,
        status="draft",
    )
    db.add(campaign)
    db.flush()
    if body.approval_required:
        db.add(CampaignApproval(
            id=str(uuid.uuid4()),
            campaign_id=campaign.id,
            status="pending",
            request_reason=approval_reason,
            requested_by=principal["actor"],
        ))
    db.commit()
    audit(
        db,
        principal["actor"],
        "campaign.created",
        "campaign",
        campaign.id,
        {
            "name": campaign.name,
            "reboot_policy": reboot_policy,
            "maintenance_window": maintenance_window_state(policy_payload),
            "post_patch_validation": body.post_patch_validation,
            "health_gate_enabled": body.health_gate_enabled,
            "health_gate_required": body.health_gate_require_telemetry,
            "critical_services": len(body.critical_services),
            "application_health_checks": len(body.application_health_checks),
            "prepare_rollback": body.prepare_rollback,
            "rollback_required": body.rollback_required,
            "target_agent_id": target_agent.id if target_agent else "",
            "target_agent_count": len(target_agent_ids),
            "target_agent_ids": target_agent_ids[:50],
            "source_finding_id": target_finding.id if target_finding else "",
            "approval_required": body.approval_required,
            "approval_reason": approval_reason if body.approval_required else "",
            "rollout_plan": rollout_plan,
            "soak_minutes": int(body.soak_minutes),
            "promotion_min_success_rate": float(body.promotion_min_success_rate),
            "promotion_max_success_drop": float(body.promotion_max_success_drop),
            "pause_on_failure": bool(body.pause_on_failure),
        },
    )
    return serialize_campaign(campaign)




def serialize_freeze_window(item: PatchFreezeWindow, reference: datetime | None = None) -> dict:
    reference = reference or now()
    starts = item.starts_at if item.starts_at.tzinfo else item.starts_at.replace(tzinfo=timezone.utc)
    ends = item.ends_at if item.ends_at.tzinfo else item.ends_at.replace(tzinfo=timezone.utc)
    return {
        "id": item.id,
        "name": item.name,
        "target_os": item.target_os,
        "target_tag": item.target_tag,
        "starts_at": starts.isoformat(),
        "ends_at": ends.isoformat(),
        "enabled": item.enabled,
        "active": bool(item.enabled and starts <= reference < ends),
        "reason": item.reason,
        "created_by": item.created_by,
        "updated_by": item.updated_by,
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "updated_at": item.updated_at.isoformat() if item.updated_at else None,
    }


def freeze_window_matches_campaign(window: PatchFreezeWindow, campaign: Campaign, reference: datetime | None = None) -> bool:
    reference = reference or now()
    if not window.enabled:
        return False
    starts = window.starts_at if window.starts_at.tzinfo else window.starts_at.replace(tzinfo=timezone.utc)
    ends = window.ends_at if window.ends_at.tzinfo else window.ends_at.replace(tzinfo=timezone.utc)
    if not (starts <= reference < ends):
        return False
    target_os = str(window.target_os or "all").lower()
    campaign_os = str(campaign.target_os or "all").lower()
    if target_os not in {"", "all"} and target_os != campaign_os:
        return False
    target_tag = str(window.target_tag or "").strip()
    campaign_tag = str(campaign.target_tag or "").strip()
    if target_tag and target_tag != campaign_tag:
        return False
    return True


def active_freeze_windows_for_campaign(db: Session, campaign: Campaign, reference: datetime | None = None) -> list[PatchFreezeWindow]:
    reference = reference or now()
    candidates = db.query(PatchFreezeWindow).filter(PatchFreezeWindow.enabled.is_(True)).all()
    return [item for item in candidates if freeze_window_matches_campaign(item, campaign, reference)]


def active_campaign_freeze_override(db: Session, campaign_id: str) -> CampaignFreezeOverride | None:
    return db.query(CampaignFreezeOverride).filter(
        CampaignFreezeOverride.campaign_id == campaign_id,
        CampaignFreezeOverride.revoked_at.is_(None),
    ).first()


def campaign_freeze_guard(db: Session, campaign: Campaign, reference: datetime | None = None) -> dict:
    windows = active_freeze_windows_for_campaign(db, campaign, reference)
    override = active_campaign_freeze_override(db, campaign.id)
    return {
        "blocked": bool(windows and not override),
        "windows": [serialize_freeze_window(item, reference) for item in windows],
        "override": {
            "id": override.id,
            "reason": override.reason,
            "approved_by": override.approved_by,
            "approved_at": override.approved_at.isoformat() if override.approved_at else None,
        } if override else None,
    }


def enforce_campaign_freeze_guard(db: Session, campaign: Campaign):
    guard = campaign_freeze_guard(db, campaign)
    if guard["blocked"]:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "campaign blocked by active change freeze window",
                "freeze_windows": [
                    {"id": item["id"], "name": item["name"], "reason": item["reason"], "ends_at": item["ends_at"]}
                    for item in guard["windows"]
                ],
            },
        )
    return guard


def serialize_patch_block_rule(rule: PatchBlockRule, reference: datetime | None = None) -> dict:
    reference = reference or now()
    expires_at = rule.expires_at
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    expired = bool(expires_at and expires_at <= reference)
    return {
        "id": rule.id,
        "name": rule.name,
        "patch_ref": rule.patch_ref,
        "target_os": rule.target_os,
        "target_tag": rule.target_tag,
        "reason": rule.reason,
        "enabled": rule.enabled,
        "expired": expired,
        "active": bool(rule.enabled and not expired),
        "expires_at": expires_at.isoformat() if expires_at else None,
        "created_by": rule.created_by,
        "updated_by": rule.updated_by,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "updated_at": rule.updated_at.isoformat() if rule.updated_at else None,
    }


def active_patch_block_rules(db: Session, reference: datetime | None = None) -> list[PatchBlockRule]:
    reference = reference or now()
    rules = db.query(PatchBlockRule).filter(PatchBlockRule.enabled.is_(True)).order_by(
        PatchBlockRule.patch_ref.asc(),
        PatchBlockRule.name.asc(),
    ).all()
    active = []
    for rule in rules:
        expires_at = rule.expires_at
        if expires_at is not None and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at is not None and expires_at <= reference:
            continue
        active.append(rule)
    return active


def patch_block_rule_matches(rule: PatchBlockRule, patch_ref: str, agent: Agent) -> bool:
    if str(rule.patch_ref or "").strip().lower() != str(patch_ref or "").strip().lower():
        return False
    target_os = str(rule.target_os or "all").strip().lower()
    if target_os not in {"", "all"} and str(agent.os_family or "").strip().lower() != target_os:
        return False
    target_tag = str(rule.target_tag or "").strip()
    if target_tag:
        tags = {str(tag).strip().lower() for tag in load(agent.tags, []) if str(tag).strip()}
        if target_tag.lower() not in tags:
            return False
    return True


def campaign_patch_blockers(
    db: Session,
    campaign: Campaign,
    agents: list[Agent],
    reference: datetime | None = None,
) -> list[dict]:
    if campaign.action != "install_updates" or not agents:
        return []
    payload = load(campaign.payload_json, {})
    patch_refs = sorted({
        str(value).strip()
        for value in payload.get("packages", [])
        if str(value).strip()
    })
    if not patch_refs:
        return []

    blockers = []
    for rule in active_patch_block_rules(db, reference):
        matched_agents = []
        matched_refs = []
        for patch_ref in patch_refs:
            matching = [agent for agent in agents if patch_block_rule_matches(rule, patch_ref, agent)]
            if matching:
                matched_refs.append(patch_ref)
                matched_agents.extend(matching)
        if not matched_agents:
            continue
        unique_agents = {agent.id: agent for agent in matched_agents}
        blockers.append({
            "rule_id": rule.id,
            "rule_name": rule.name,
            "patch_ref": rule.patch_ref,
            "matched_patch_refs": sorted(set(matched_refs)),
            "target_os": rule.target_os,
            "target_tag": rule.target_tag,
            "reason": rule.reason,
            "expires_at": rule.expires_at.isoformat() if rule.expires_at else None,
            "matched_assets": len(unique_agents),
            "assets": [
                {"agent_id": agent.id, "hostname": agent.hostname}
                for agent in sorted(unique_agents.values(), key=lambda item: item.hostname.lower())[:20]
            ],
        })
    return blockers



def serialize_campaign_preflight_snapshot(item: CampaignPreflightSnapshot, include_result: bool = False) -> dict:
    data = {
        "id": item.id,
        "campaign_id": item.campaign_id,
        "readiness": item.readiness,
        "deploy_allowed": bool(item.deploy_allowed),
        "summary": load(item.summary_json, {}),
        "result_sha256": item.result_sha256,
        "actor": item.actor,
        "source": item.source,
        "created_at": item.created_at.isoformat() if item.created_at else None,
    }
    if include_result:
        data["result"] = load(item.result_json, {})
    return data


def latest_campaign_preflight_snapshot(db: Session, campaign_id: str):
    return db.query(CampaignPreflightSnapshot).filter(
        CampaignPreflightSnapshot.campaign_id == campaign_id
    ).order_by(CampaignPreflightSnapshot.created_at.desc()).first()


def campaign_preflight_drift(previous_result: dict | None, current_result: dict) -> dict:
    if not previous_result:
        return {
            "status": "NO_BASELINE",
            "changed": False,
            "degraded": 0,
            "improved": 0,
            "changes": [],
        }

    rank = {"passed": 0, "warning": 1, "blocked": 2}
    previous_checks = {
        str(item.get("key") or ""): item
        for item in previous_result.get("checks", [])
        if str(item.get("key") or "")
    }
    current_checks = {
        str(item.get("key") or ""): item
        for item in current_result.get("checks", [])
        if str(item.get("key") or "")
    }
    changes = []

    for key in sorted(set(previous_checks) | set(current_checks)):
        old = previous_checks.get(key)
        new = current_checks.get(key)
        old_status = str((old or {}).get("status") or "missing")
        new_status = str((new or {}).get("status") or "missing")
        old_message = str((old or {}).get("message") or "")
        new_message = str((new or {}).get("message") or "")
        if old_status == new_status and old_message == new_message:
            continue

        if old is None:
            direction = "new"
        elif new is None:
            direction = "removed"
        else:
            old_rank = rank.get(old_status, 1)
            new_rank = rank.get(new_status, 1)
            direction = "degraded" if new_rank > old_rank else "improved" if new_rank < old_rank else "changed"

        changes.append({
            "key": key,
            "label": str((new or old or {}).get("label") or key),
            "direction": direction,
            "from_status": old_status,
            "to_status": new_status,
            "from_message": old_message,
            "to_message": new_message,
        })

    degraded = sum(1 for item in changes if item["direction"] == "degraded")
    improved = sum(1 for item in changes if item["direction"] == "improved")
    if degraded:
        status = "DEGRADED"
    elif improved and not any(item["direction"] in {"changed", "new"} for item in changes):
        status = "IMPROVED"
    elif changes:
        status = "CHANGED"
    else:
        status = "UNCHANGED"

    return {
        "status": status,
        "changed": bool(changes),
        "degraded": degraded,
        "improved": improved,
        "changes": changes,
    }


def persist_campaign_preflight_snapshot(
    db: Session,
    campaign: Campaign,
    result: dict,
    actor: str,
    source: str = "manual",
) -> CampaignPreflightSnapshot:
    canonical = dump(result)
    item = CampaignPreflightSnapshot(
        id=str(uuid.uuid4()),
        campaign_id=campaign.id,
        readiness=str(result.get("readiness") or "REVIEW"),
        deploy_allowed=bool(result.get("deploy_allowed")),
        summary_json=dump(result.get("summary") or {}),
        result_json=canonical,
        result_sha256=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        actor=actor,
        source=source,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


def campaign_required_capabilities(campaign: Campaign) -> list[str]:
    payload = load(campaign.payload_json, {})
    required = {"job_leases_v1"}

    if campaign.action == "scan_updates":
        required.add("scan_updates")
    elif campaign.action == "install_updates":
        required.add("install_updates")
        if payload.get("prepare_rollback", True):
            required.add("rollback_checkpoint_v1")
        health_policy = payload.get("health_policy")
        if isinstance(health_policy, dict) and health_policy.get("enabled"):
            required.add("health_telemetry_v1")
    elif campaign.action == "rollback_checkpoint":
        required.add("rollback_restore_v1")
    elif campaign.action == "activate_agent_update":
        required.add("signed_update_activation_v1")
    elif campaign.action == "clear_agent_update_quarantine":
        required.add("signed_update_quarantine_v1")

    return sorted(required)


def campaign_preflight(
    db: Session,
    campaign: Campaign,
    reference: datetime | None = None,
) -> dict:
    reference = reference or now()
    payload = load(campaign.payload_json, {})
    candidates = campaign_candidates(db, campaign)
    selected = agents_for_ring(db, campaign, campaign.ring_percent)
    checks = []

    def add_check(key: str, label: str, status: str, message: str, *, blocking: bool = False, details=None):
        checks.append({
            "key": key,
            "label": label,
            "status": status,
            "blocking": bool(blocking),
            "message": message,
            "details": details or {},
        })

    if not candidates:
        add_check(
            "scope",
            "Target scope",
            "blocked",
            "nenhum endpoint corresponde ao escopo da campanha",
            blocking=True,
            details={"candidates": 0, "selected_ring": 0},
        )
    else:
        add_check(
            "scope",
            "Target scope",
            "passed",
            f"{len(candidates)} endpoint(s) elegíveis; {len(selected)} no ring inicial de {campaign.ring_percent}%",
            details={"candidates": len(candidates), "selected_ring": len(selected), "ring_percent": campaign.ring_percent},
        )

    approval = serialize_campaign_approval(campaign)
    if approval.get("required") and approval.get("status") != "approved":
        add_check(
            "approval",
            "Approval Gate",
            "blocked",
            f"aprovação administrativa está {approval.get('status') or 'pendente'}",
            blocking=True,
            details=approval,
        )
    else:
        add_check(
            "approval",
            "Approval Gate",
            "passed",
            "aprovação atendida" if approval.get("required") else "aprovação não exigida",
            details=approval,
        )

    freeze = campaign_freeze_guard(db, campaign, reference)
    if freeze["blocked"]:
        add_check(
            "change_freeze",
            "Change Freeze",
            "blocked",
            f"{len(freeze['windows'])} janela(s) ativa(s) bloqueiam a mudança",
            blocking=True,
            details=freeze,
        )
    elif freeze["windows"] and freeze["override"]:
        add_check(
            "change_freeze",
            "Change Freeze",
            "warning",
            "freeze ativa com emergency override auditado",
            details=freeze,
        )
    else:
        add_check(
            "change_freeze",
            "Change Freeze",
            "passed",
            "nenhuma freeze ativa aplicável",
            details=freeze,
        )

    patch_blockers = campaign_patch_blockers(db, campaign, selected, reference)
    if patch_blockers:
        add_check(
            "patch_guard",
            "Patch Guard",
            "blocked",
            f"{len(patch_blockers)} regra(s) bloqueiam patch no ring selecionado",
            blocking=True,
            details={"blockers": patch_blockers},
        )
    else:
        add_check(
            "patch_guard",
            "Patch Guard",
            "passed",
            "nenhum bloqueio de patch aplicável",
        )

    required_capabilities = campaign_required_capabilities(campaign)
    incompatible = []
    stale = []
    mtls_missing = []
    for agent in selected:
        runtime = agent_runtime_metadata(agent)
        available = set(runtime.get("capabilities") or [])
        missing = sorted(set(required_capabilities) - available)
        if runtime.get("status") != "supported" or missing:
            incompatible.append({
                "agent_id": agent.id,
                "hostname": agent.hostname,
                "status": runtime.get("status"),
                "version": runtime.get("version"),
                "protocol": runtime.get("protocol"),
                "missing_capabilities": missing,
            })
        if not agent_heartbeat_fresh(agent):
            stale.append({"agent_id": agent.id, "hostname": agent.hostname, "last_seen": agent.last_seen.isoformat() if agent.last_seen else None})
        if AGENT_MTLS_REQUIRED and not agent.client_cert_fingerprint:
            mtls_missing.append({"agent_id": agent.id, "hostname": agent.hostname})

    if incompatible:
        enforced = bool(AGENT_ENFORCE_COMPATIBILITY)
        add_check(
            "agent_compatibility",
            "Agent compatibility",
            "blocked" if enforced else "warning",
            f"{len(incompatible)} endpoint(s) não atendem versão/protocolo/capabilities exigidas" +
            ("; enforcement ativo" if enforced else "; enforcement está em observação"),
            blocking=enforced,
            details={
                "required_capabilities": required_capabilities,
                "incompatible": incompatible[:20],
                "enforced": enforced,
            },
        )
    else:
        add_check(
            "agent_compatibility",
            "Agent compatibility",
            "passed",
            f"{len(selected)} endpoint(s) atendem as capabilities exigidas",
            details={"required_capabilities": required_capabilities, "enforced": AGENT_ENFORCE_COMPATIBILITY},
        )

    if stale:
        add_check(
            "heartbeat",
            "Agent freshness",
            "warning",
            f"{len(stale)} endpoint(s) sem heartbeat recente",
            details={"stale": stale[:20], "max_age_seconds": AGENT_UPDATE_MAX_HEARTBEAT_AGE_SECONDS},
        )
    else:
        add_check(
            "heartbeat",
            "Agent freshness",
            "passed",
            "heartbeats do ring estão recentes" if selected else "sem endpoints selecionados",
        )

    if mtls_missing:
        add_check(
            "mtls",
            "Agent mTLS",
            "blocked",
            f"{len(mtls_missing)} endpoint(s) sem fingerprint mTLS vinculada",
            blocking=True,
            details={"missing": mtls_missing[:20], "required": True},
        )
    else:
        add_check(
            "mtls",
            "Agent mTLS",
            "passed",
            "mTLS atendido" if AGENT_MTLS_REQUIRED else "mTLS não é obrigatório neste ambiente",
            details={"required": AGENT_MTLS_REQUIRED},
        )

    window = maintenance_window_state(payload, reference)
    if window.get("enabled") and not window.get("eligible_now"):
        add_check(
            "maintenance_window",
            "Maintenance window",
            "warning",
            window.get("reason") or "fora da janela de manutenção",
            details=window,
        )
    else:
        add_check(
            "maintenance_window",
            "Maintenance window",
            "passed",
            window.get("reason") or "janela disponível",
            details=window,
        )

    if campaign.action == "install_updates":
        packages = sorted({str(value).strip() for value in payload.get("packages", []) if str(value).strip()})
        confidence_map = {
            str(item.get("patch_ref") or "").strip().lower(): item
            for item in patch_confidence_report(db, limit=1000).get("items", [])
        }
        confidence_items = []
        warning_refs = []
        for ref in packages:
            item = confidence_map.get(ref.lower())
            if item:
                confidence_items.append(item)
                if item.get("confidence") in {"low", "insufficient_data"}:
                    warning_refs.append(ref)
            else:
                confidence_items.append({"patch_ref": ref, "confidence": "insufficient_data", "completed_jobs": 0})
                warning_refs.append(ref)
        if packages and warning_refs:
            add_check(
                "patch_confidence",
                "Patch Confidence",
                "warning",
                f"{len(warning_refs)} patch(es) sem confiança local suficiente",
                details={"items": confidence_items},
            )
        elif packages:
            add_check(
                "patch_confidence",
                "Patch Confidence",
                "passed",
                "histórico local de deployment disponível para as patches",
                details={"items": confidence_items},
            )
        else:
            add_check(
                "patch_confidence",
                "Patch Confidence",
                "warning",
                "campanha de instalação sem patch reference explícita",
                details={"items": []},
            )

    blockers = [item for item in checks if item["blocking"]]
    warnings = [item for item in checks if item["status"] == "warning"]
    if blockers:
        readiness = "BLOCKED"
    elif warnings:
        readiness = "REVIEW"
    else:
        readiness = "READY"

    return {
        "generated_at": reference.isoformat(),
        "campaign_id": campaign.id,
        "campaign_name": campaign.name,
        "campaign_status": campaign.status,
        "readiness": readiness,
        "deploy_allowed": not blockers,
        "summary": {
            "checks": len(checks),
            "passed": sum(1 for item in checks if item["status"] == "passed"),
            "warnings": len(warnings),
            "blockers": len(blockers),
            "candidates": len(candidates),
            "selected_ring": len(selected),
        },
        "checks": checks,
        "note": "Preflight is an explicit checklist of operational controls. It does not compute a hidden readiness score.",
    }


def campaign_candidates(db: Session, campaign: Campaign):
    candidates = []
    payload = load(campaign.payload_json, {})
    target_agent_id = str(payload.get("target_agent_id") or "")
    snapshot_ids = payload.get("target_agent_ids")
    snapshot_set = (
        {str(item) for item in snapshot_ids if str(item)}
        if isinstance(snapshot_ids, list) and snapshot_ids
        else set()
    )
    for agent in db.query(Agent).all():
        if target_agent_id and agent.id != target_agent_id:
            continue
        if snapshot_set and agent.id not in snapshot_set:
            continue
        if campaign.target_os != "all" and agent.os_family != campaign.target_os:
            continue
        tags = load(agent.tags, [])
        if campaign.target_tag and campaign.target_tag not in tags:
            continue
        candidates.append(agent)
    return sorted(candidates, key=lambda agent: ring_bucket(agent.id))


def agents_for_ring(db: Session, campaign: Campaign, percent: int):
    candidates = campaign_candidates(db, campaign)
    if not candidates:
        return []
    target_count = max(1, math.ceil(len(candidates) * percent / 100))
    return candidates[:min(len(candidates), target_count)]


def add_ring_jobs(db: Session, campaign: Campaign, agents, ring_percent: int):
    base_payload = load(campaign.payload_json, {})
    created = []
    for agent in agents:
        payload = {
            **base_payload,
            "_ring_percent": ring_percent,
            "_baseline_pending_updates": agent.pending_updates,
            "_baseline_critical_updates": agent.critical_updates,
        }
        job = PatchJob(
            id=str(uuid.uuid4()),
            campaign_id=campaign.id,
            agent_id=agent.id,
            action=campaign.action,
            payload_json=dump(payload),
            not_before=campaign.not_before,
            status="pending",
        )
        db.add(job)
        remediation_evidence_for_job(db, job, payload)
        created.append(job)
    return created



@app.get("/api/admin/campaigns/{campaign_id}/preflight")
def get_campaign_preflight(
    campaign_id: str,
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    campaign = db.get(Campaign, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="campaign not found")
    result = campaign_preflight(db, campaign)
    latest = latest_campaign_preflight_snapshot(db, campaign.id)
    previous_result = load(latest.result_json, {}) if latest else None
    result["latest_snapshot"] = serialize_campaign_preflight_snapshot(latest) if latest else None
    result["drift"] = campaign_preflight_drift(previous_result, result)
    return result


@app.post("/api/admin/campaigns/{campaign_id}/preflight/snapshot")
def snapshot_campaign_preflight(
    campaign_id: str,
    principal=Depends(require_operator),
    db: Session = Depends(get_db),
):
    campaign = db.get(Campaign, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="campaign not found")

    result = campaign_preflight(db, campaign)
    previous = latest_campaign_preflight_snapshot(db, campaign.id)
    previous_result = load(previous.result_json, {}) if previous else None
    drift = campaign_preflight_drift(previous_result, result)
    item = persist_campaign_preflight_snapshot(
        db,
        campaign,
        result,
        principal["actor"],
        "manual",
    )
    audit(
        db,
        principal["actor"],
        "campaign.preflight.snapshot",
        "campaign",
        campaign.id,
        {
            "snapshot_id": item.id,
            "readiness": item.readiness,
            "deploy_allowed": item.deploy_allowed,
            "result_sha256": item.result_sha256,
            "drift": drift,
        },
    )
    return {
        "snapshot": serialize_campaign_preflight_snapshot(item, include_result=True),
        "drift": drift,
    }


@app.get("/api/admin/campaigns/{campaign_id}/preflight/history")
def get_campaign_preflight_history(
    campaign_id: str,
    limit: int = 50,
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    if not db.get(Campaign, campaign_id):
        raise HTTPException(status_code=404, detail="campaign not found")
    items = db.query(CampaignPreflightSnapshot).filter(
        CampaignPreflightSnapshot.campaign_id == campaign_id
    ).order_by(CampaignPreflightSnapshot.created_at.desc()).limit(max(1, min(limit, 200))).all()
    return [serialize_campaign_preflight_snapshot(item) for item in items]


@app.post("/api/admin/campaigns/{campaign_id}/deploy")
def deploy_campaign(campaign_id: str, principal=Depends(require_operator), db: Session = Depends(get_db)):
    campaign = db.get(Campaign, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="campaign not found")
    if campaign.status != "draft":
        raise HTTPException(status_code=409, detail="campaign already deployed")

    preflight = campaign_preflight(db, campaign)
    previous_snapshot = latest_campaign_preflight_snapshot(db, campaign.id)
    previous_result = load(previous_snapshot.result_json, {}) if previous_snapshot else None
    preflight_drift = campaign_preflight_drift(previous_result, preflight)
    deploy_snapshot = persist_campaign_preflight_snapshot(
        db,
        campaign,
        preflight,
        principal["actor"],
        "deploy_attempt",
    )

    enforce_campaign_freeze_guard(db, campaign)

    approval_state = serialize_campaign_approval(campaign)
    if approval_state["required"] and approval_state["status"] != "approved":
        raise HTTPException(
            status_code=409,
            detail={
                "message": "campaign requires administrative approval before deploy",
                "approval": approval_state,
            },
        )

    selected = agents_for_ring(db, campaign, campaign.ring_percent)
    if not selected:
        raise HTTPException(status_code=409, detail="no agents matched campaign target")

    blockers = campaign_patch_blockers(db, campaign, selected)
    if blockers:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "patch deployment blocked by Patch Guard",
                "blockers": blockers,
            },
        )

    additional_blockers = [
        item for item in preflight["checks"]
        if item.get("blocking") and item.get("key") in {"agent_compatibility", "mtls"}
    ]
    if additional_blockers:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "campaign preflight blocked deployment",
                "preflight": preflight,
                "blockers": additional_blockers,
            },
        )

    add_ring_jobs(db, campaign, selected, campaign.ring_percent)
    campaign.status = "deployed"
    record_campaign_ring_decision(
        db,
        campaign,
        0,
        campaign.ring_percent,
        "DEPLOY",
        "initial ring deployed",
        campaign_health(campaign),
        principal["actor"],
    )
    db.commit()
    audit(
        db,
        principal["actor"],
        "campaign.deployed",
        "campaign",
        campaign.id,
        {
            "agents": len(selected),
            "ring_percent": campaign.ring_percent,
            "preflight_snapshot_id": deploy_snapshot.id,
            "preflight_readiness": preflight.get("readiness"),
            "preflight_drift": preflight_drift,
        },
    )
    return {
        "ok": True,
        "agents_selected": len(selected),
        "ring_percent": campaign.ring_percent,
        "preflight_snapshot": serialize_campaign_preflight_snapshot(deploy_snapshot),
        "preflight_drift": preflight_drift,
        "campaign": serialize_campaign(campaign),
    }





def _evidence_canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _evidence_sha256(value: Any) -> str:
    return hashlib.sha256(_evidence_canonical_json(value).encode("utf-8")).hexdigest()


def campaign_evidence_pack(db: Session, campaign: Campaign, reference: datetime | None = None) -> dict:
    reference = reference or now()

    preflight_items = db.query(CampaignPreflightSnapshot).filter(
        CampaignPreflightSnapshot.campaign_id == campaign.id
    ).order_by(CampaignPreflightSnapshot.created_at.asc()).all()
    ring_items = db.query(CampaignRingDecision).filter(
        CampaignRingDecision.campaign_id == campaign.id
    ).order_by(CampaignRingDecision.created_at.asc()).all()

    jobs = db.query(PatchJob).filter(
        PatchJob.campaign_id == campaign.id
    ).order_by(PatchJob.created_at.asc(), PatchJob.id.asc()).all()
    job_ids = [job.id for job in jobs]

    audit_query = db.query(AuditEvent).filter(
        (
            (AuditEvent.object_type == "campaign")
            & (AuditEvent.object_id == campaign.id)
        )
        | (
            (AuditEvent.object_type == "job")
            & (AuditEvent.object_id.in_(job_ids if job_ids else ["__none__"]))
        )
    )
    audit_items = audit_query.order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc()).all()

    freeze_override = db.query(CampaignFreezeOverride).filter(
        CampaignFreezeOverride.campaign_id == campaign.id
    ).first()

    sections = {
        "campaign": serialize_campaign(campaign),
        "approval": serialize_campaign_approval(campaign),
        "preflight_snapshots": [
            serialize_campaign_preflight_snapshot(item, include_result=True)
            for item in preflight_items
        ],
        "ring_decisions": [
            serialize_campaign_ring_decision(item)
            for item in ring_items
        ],
        "jobs": [
            serialize_job(job)
            for job in jobs
        ],
        "freeze_override": (
            {
                "id": freeze_override.id,
                "reason": freeze_override.reason,
                "approved_by": freeze_override.approved_by,
                "approved_at": freeze_override.approved_at.isoformat() if freeze_override.approved_at else None,
                "revoked_by": freeze_override.revoked_by,
                "revoked_at": freeze_override.revoked_at.isoformat() if freeze_override.revoked_at else None,
                "revoke_reason": freeze_override.revoke_reason,
            }
            if freeze_override else None
        ),
        "audit_events": [
            {
                "id": item.id,
                "actor": item.actor,
                "event_type": item.event_type,
                "object_type": item.object_type,
                "object_id": item.object_id,
                "details": load(item.details_json, {}),
                "created_at": item.created_at.isoformat() if item.created_at else None,
            }
            for item in audit_items
        ],
    }

    section_hashes = {
        key: _evidence_sha256(value)
        for key, value in sections.items()
    }
    summary = {
        "preflight_snapshots": len(preflight_items),
        "ring_decisions": len(ring_items),
        "jobs": len(jobs),
        "job_statuses": {
            status: sum(1 for job in jobs if job.status == status)
            for status in sorted({job.status for job in jobs})
        },
        "audit_events": len(audit_items),
        "freeze_override_present": freeze_override is not None,
        "approval_status": serialize_campaign_approval(campaign).get("status"),
        "current_ring_percent": campaign.ring_percent,
        "campaign_status": campaign.status,
    }

    content = {
        "schema": "be-safe-campaign-evidence-pack/v1",
        "generated_at": reference.isoformat(),
        "campaign_id": campaign.id,
        "summary": summary,
        "section_hashes": section_hashes,
        "sections": sections,
    }
    pack_sha256 = _evidence_sha256(content)

    return {
        **content,
        "manifest": {
            "hash_algorithm": "SHA-256",
            "pack_sha256": pack_sha256,
            "section_hashes": section_hashes,
            "verification": "Recompute SHA-256 over UTF-8 JSON with sorted keys and compact separators for the pack without the manifest field.",
        },
    }


@app.get("/api/admin/campaigns/{campaign_id}/evidence-pack")
def get_campaign_evidence_pack(
    campaign_id: str,
    principal=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    campaign = db.get(Campaign, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="campaign not found")
    pack = campaign_evidence_pack(db, campaign)
    audit(
        db,
        principal["actor"],
        "campaign.evidence_pack.exported",
        "campaign",
        campaign.id,
        {
            "pack_sha256": pack["manifest"]["pack_sha256"],
            "summary": pack["summary"],
        },
    )
    return pack


@app.get("/api/admin/campaigns/{campaign_id}/promotion-analysis")
def get_campaign_promotion_analysis(
    campaign_id: str,
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    campaign = db.get(Campaign, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="campaign not found")
    rollout = campaign_rollout_governance(campaign)
    return {
        "campaign_id": campaign.id,
        "campaign_name": campaign.name,
        "rollout": rollout,
        "regression": rollout.get("regression"),
        "recommendation": rollout.get("recommendation"),
    }


@app.get("/api/admin/campaigns/{campaign_id}/rollout-governance")
def get_campaign_rollout_governance(
    campaign_id: str,
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    campaign = db.get(Campaign, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="campaign not found")
    return campaign_rollout_governance(campaign)


@app.get("/api/admin/campaigns/{campaign_id}/ring-history")
def get_campaign_ring_history(
    campaign_id: str,
    limit: int = 100,
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    if not db.get(Campaign, campaign_id):
        raise HTTPException(status_code=404, detail="campaign not found")
    items = db.query(CampaignRingDecision).filter(
        CampaignRingDecision.campaign_id == campaign_id
    ).order_by(CampaignRingDecision.created_at.desc()).limit(max(1, min(limit, 500))).all()
    return [serialize_campaign_ring_decision(item) for item in items]


@app.post("/api/admin/campaigns/{campaign_id}/advance")
def advance_campaign(
    campaign_id: str,
    body: RingAdvance,
    principal=Depends(require_operator),
    db: Session = Depends(get_db),
):
    campaign = db.get(Campaign, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="campaign not found")
    if campaign.status != "deployed":
        raise HTTPException(status_code=409, detail="campaign must be deployed before advancing")
    enforce_campaign_freeze_guard(db, campaign)
    if body.target_percent <= campaign.ring_percent:
        raise HTTPException(status_code=400, detail="target ring must be greater than current ring")
    if campaign.action == "activate_agent_update" and principal.get("role") != "admin":
        raise HTTPException(status_code=403, detail="admin role required to advance agent update rollout")

    health = campaign_health(campaign)
    rollout_state = campaign_rollout_governance(campaign)
    if rollout_state["state"] == "SOAK" and not body.override_health_gate:
        raise HTTPException(
            status_code=409,
            detail={"message": "rollout soak time has not elapsed", "rollout": rollout_state},
        )
    if rollout_state["state"] == "PAUSE" and not body.override_health_gate:
        raise HTTPException(
            status_code=409,
            detail={"message": "rollout governance paused ring promotion", "rollout": rollout_state},
        )
    configured_next = rollout_state.get("next_ring")
    if rollout_state.get("plan_enforced") and configured_next is not None and body.target_percent != configured_next and not body.override_health_gate:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "target ring does not match configured rollout plan",
                "expected_target_percent": configured_next,
                "rollout": rollout_state,
            },
        )
    if campaign.action == "activate_agent_update" and body.override_health_gate:
        raise HTTPException(
            status_code=400,
            detail="health gate override is disabled for agent update rollouts",
        )
    if not health["ready"] and (
        campaign.action == "activate_agent_update" or not body.override_health_gate
    ):
        raise HTTPException(
            status_code=409,
            detail={"message": "health gate blocked ring advance", "health": health},
        )

    target_agents = agents_for_ring(db, campaign, body.target_percent)
    existing_agent_ids = {job.agent_id for job in campaign.jobs}
    new_agents = [agent for agent in target_agents if agent.id not in existing_agent_ids]

    if campaign.action == "activate_agent_update":
        payload = load(campaign.payload_json, {})
        expected_version = str(payload.get("expected_version") or "")
        release_binding = signed_release_binding(expected_version)
        original_binding = payload.get("release_binding") if isinstance(payload.get("release_binding"), dict) else {}
        if any(
            str(original_binding.get(key) or "").lower() != str(release_binding.get(key) or "").lower()
            for key in ("version", "artifact_sha256", "source_commit", "signing_key_id")
        ):
            raise HTTPException(
                status_code=409,
                detail="published signed release changed since rollout creation",
            )
        unavailable = []
        for agent in new_agents:
            ok, reason = agent_update_rollout_eligibility(
                db,
                agent,
                expected_version,
                campaign.target_tag,
                release_binding,
            )
            if not ok:
                unavailable.append({
                    "agent_id": agent.id,
                    "hostname": agent.hostname,
                    "reason": reason,
                })
        if unavailable:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "one or more agents are no longer eligible for rollout advance",
                    "unavailable": unavailable[:20],
                },
            )

    if campaign.action == "install_updates":
        blockers = campaign_patch_blockers(db, campaign, new_agents)
        if blockers:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "ring advance blocked by Patch Guard",
                    "blockers": blockers,
                },
            )

    previous_ring = campaign.ring_percent
    if campaign.action == "activate_agent_update":
        payload = load(campaign.payload_json, {})
        approved_at = now()
        payload["approved_at"] = approved_at.isoformat()
        payload["approval_expires_at"] = (
            approved_at + timedelta(seconds=AGENT_UPDATE_APPROVAL_TTL_SECONDS)
        ).isoformat()
        campaign.payload_json = dump(payload)
    add_ring_jobs(db, campaign, new_agents, body.target_percent)
    campaign.ring_percent = body.target_percent
    record_campaign_ring_decision(
        db,
        campaign,
        previous_ring,
        body.target_percent,
        "PROMOTE_OVERRIDE" if body.override_health_gate else "PROMOTE",
        "ring promotion approved with health override" if body.override_health_gate else "rollout governance allowed ring promotion",
        health,
        principal["actor"],
    )
    db.commit()

    audit(
        db,
        principal["actor"],
        "campaign.advanced",
        "campaign",
        campaign.id,
        {
            "from_ring": previous_ring,
            "to_ring": body.target_percent,
            "new_agents": len(new_agents),
            "target_agents": len(target_agents),
            "health_gate_overridden": body.override_health_gate,
            "previous_health": health,
        },
    )

    return {
        "ok": True,
        "from_ring": previous_ring,
        "to_ring": body.target_percent,
        "new_agents": len(new_agents),
        "target_agents": len(target_agents),
        "campaign": serialize_campaign(campaign),
    }


@app.post("/api/admin/jobs/{job_id}/retry")
def retry_stalled_job(
    job_id: str,
    body: JobRetryRequest,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    if not body.acknowledge_risk:
        raise HTTPException(status_code=400, detail="explicit retry risk acknowledgement is required")

    job = db.get(PatchJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    if job.status != "stalled":
        raise HTTPException(status_code=409, detail="only stalled jobs can be retried")

    previous = {
        "attempt_count": job.attempt_count,
        "claimed_at": job.claimed_at.isoformat() if job.claimed_at else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "last_lease_at": job.last_lease_at.isoformat() if job.last_lease_at else None,
        "error": job.error,
    }

    job.status = "pending"
    job.claimed_at = None
    job.claim_token_hash = ""
    job.lease_expires_at = None
    job.last_lease_at = None
    job.started_at = None
    job.finished_at = None
    job.result_json = "{}"
    job.error = ""
    db.commit()

    audit(
        db,
        principal["actor"],
        "job.retry.approved",
        "job",
        job.id,
        {"reason": body.reason, "previous_attempt": previous},
    )
    return {"ok": True, "job": serialize_job(job)}


@app.post("/api/admin/jobs/{job_id}/rollback")
def approve_rollback(
    job_id: str,
    body: RollbackRequest,
    principal=Depends(require_admin),
    db: Session = Depends(get_db),
):
    if not body.acknowledge_risk:
        raise HTTPException(status_code=400, detail="explicit rollback risk acknowledgement is required")

    original=db.get(PatchJob,job_id)
    if not original:
        raise HTTPException(status_code=404, detail="job not found")

    state=rollback_state(original)
    if state.get("status") != "eligible":
        raise HTTPException(status_code=409, detail={"message":"rollback is not eligible","rollback":state})

    checkpoint=state.get("checkpoint") or {}
    if checkpoint.get("method") != "windows_restore_point":
        raise HTTPException(status_code=409, detail="automatic rollback provider is not supported")

    try:
        sequence=int(checkpoint.get("sequence"))
    except Exception as exc:
        raise HTTPException(status_code=409, detail="restore point evidence is incomplete") from exc

    original_payload=load(original.payload_json,{})
    payload={
        "method":"windows_restore_point",
        "restore_point_sequence":sequence,
        "_rollback_of_job_id":original.id,
        "approved_reason":body.reason,
        "maintenance_start":original_payload.get("maintenance_start",""),
        "maintenance_end":original_payload.get("maintenance_end",""),
        "maintenance_timezone":original_payload.get("maintenance_timezone","UTC"),
        "maintenance_days":original_payload.get("maintenance_days",list(range(7))),
    }
    rollback_job=PatchJob(
        id=str(uuid.uuid4()),
        campaign_id=original.campaign_id,
        agent_id=original.agent_id,
        action="rollback_checkpoint",
        payload_json=dump(payload),
        not_before=None,
        status="pending",
    )
    db.add(rollback_job)
    db.commit()
    audit(
        db,
        principal["actor"],
        "rollback.approved",
        "job",
        rollback_job.id,
        {
            "original_job_id":original.id,
            "agent_id":original.agent_id,
            "method":"windows_restore_point",
            "restore_point_sequence":sequence,
            "reason":body.reason,
        },
    )
    return {"ok":True,"rollback_job":serialize_job(rollback_job)}



@app.get("/api/admin/jobs")
def list_jobs(campaign_id: str | None = None, _=Depends(require_viewer), db: Session = Depends(get_db)):
    sweep_expired_job_leases(db)
    q = db.query(PatchJob).order_by(PatchJob.created_at.desc())
    if campaign_id:
        q = q.filter(PatchJob.campaign_id == campaign_id)
    return [serialize_job(j) for j in q.limit(500).all()]


@app.get("/api/admin/audit")
def list_audit(_=Depends(require_viewer), db: Session = Depends(get_db)):
    items = db.query(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(500).all()
    return [{
        "id": e.id,
        "actor": e.actor,
        "event_type": e.event_type,
        "object_type": e.object_type,
        "object_id": e.object_id,
        "details": load(e.details_json, {}),
        "created_at": e.created_at.isoformat(),
    } for e in items]
