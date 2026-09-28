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
from sqlalchemy.orm import Session, selectinload

from .database import SessionLocal, get_db
from .models import AdminSession, AdminUser, Agent, AssetRiskAcceptance, AssetRiskPolicy, AssetRiskProfile, AssetRiskSnapshot, AssetRiskTreatment, AuditEvent, Campaign, IntegrationState, PatchJob, RemediationEvidence, VulnerabilityFinding, VulnerabilitySlaException
from .schemas import AgentMtlsBindRequest, AgentUpdateActivationRequest, AgentUpdateQuarantineClearRequest, AgentUpdateRolloutCreate, AssetRiskAcceptanceCreate, AssetRiskAcceptanceRevoke, AssetRiskPolicyCreate, AssetRiskPolicyUpdate, AssetRiskProfileUpdate, AssetRiskSimulationRequest, AssetRiskTreatmentCreate, AssetRiskTreatmentUpdate, CampaignCreate, HeartbeatRequest, JobResultRequest, JobRetryRequest, LeaseRenewRequest, LoginRequest, PasswordChangeRequest, RegisterRequest, RegisterResponse, RemediationRescanRequest, RingAdvance, RollbackRequest, TagUpdate, UserCreateRequest, UserUpdateRequest, VulnerabilityImportRequest, VulnerabilitySlaExceptionCreate, VulnerabilitySlaExceptionRevoke, VulnerabilityStatusUpdate
from .security import create_session, hash_token, new_token, password_hash, password_needs_rehash, password_verify, require_admin, require_enrollment, require_operator, require_viewer, revoke_session, validate_password_strength, validate_role, validate_username
from .greenbone import fetch_findings as fetch_greenbone_findings
from .greenbone import get_config as get_greenbone_config
from .greenbone import public_config as public_greenbone_config
from .greenbone import start_task_rescan as start_greenbone_task_rescan
from .observability import metrics_response, prometheus_http_middleware, readiness_response
from .agent_updates import AgentReleaseError, load_signed_release
from .threat_intel import fetch_epss, fetch_kev, get_config as get_threat_intel_config, public_config as public_threat_intel_config

app = FastAPI(title="Be Safe Patch Manager", version="0.18.0")
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

    for row in rows:
        snapshots = db.query(AssetRiskSnapshot).filter(
            AssetRiskSnapshot.agent_id == row["agent_id"]
        ).order_by(AssetRiskSnapshot.captured_at.desc()).limit(2).all()
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
    required_success_rate = 100.0 if c.action == "activate_agent_update" else 90.0
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
        "rollout_complete": c.ring_percent >= 100,
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
    db.commit()
    unblocked = reconcile_blocked_agent_jobs(db, agent)
    return {
        "ok": True,
        "agent_compatibility": agent_runtime_metadata(agent),
        "jobs_unblocked": unblocked,
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
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    q = db.query(VulnerabilityFinding).order_by(
        VulnerabilityFinding.last_seen.desc(),
    )
    if status:
        q = q.filter(VulnerabilityFinding.status == status.lower())
    if severity:
        q = q.filter(VulnerabilityFinding.severity == severity.lower())
    if agent_id:
        q = q.filter(VulnerabilityFinding.agent_id == agent_id)
    items = [serialize_vulnerability(item) for item in q.limit(1000).all()]
    items.sort(key=lambda item: (
        item["status"] != "open",
        -(item.get("risk") or {}).get("score", 0),
        -float(item.get("cvss") or 0),
    ))
    return items


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
    finding = db.get(VulnerabilityFinding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="vulnerability finding not found")
    if finding.status != "open":
        raise HTTPException(status_code=409, detail="SLA exception requires an open vulnerability")

    expires_at = body.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= now():
        raise HTTPException(status_code=400, detail="SLA exception expiry must be in the future")
    if active_sla_exception(finding):
        raise HTTPException(status_code=409, detail="an active SLA exception already exists")

    item = VulnerabilitySlaException(
        id=str(uuid.uuid4()),
        finding=finding,
        reason=body.reason.strip(),
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

    item.revoked_at = now()
    item.revoked_by = principal["actor"]
    item.revoke_reason = body.reason.strip()
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


@app.post("/api/admin/campaigns")
def create_campaign(body: CampaignCreate, principal=Depends(require_operator), db: Session = Depends(get_db)):
    if body.action not in {"scan_updates", "install_updates"}:
        raise HTTPException(status_code=400, detail="unsupported action")

    validate_campaign_policy(body)

    target_agent = None
    if body.target_agent_id:
        target_agent = db.get(Agent, body.target_agent_id)
        if not target_agent:
            raise HTTPException(status_code=404, detail="target agent not found")

    target_finding = None
    if body.target_finding_id:
        target_finding = db.get(VulnerabilityFinding, body.target_finding_id)
        if not target_finding:
            raise HTTPException(status_code=404, detail="source vulnerability finding not found")
        if target_agent and target_finding.agent_id and target_finding.agent_id != target_agent.id:
            raise HTTPException(status_code=400, detail="vulnerability finding does not belong to target agent")

    if body.rollback_required and not body.prepare_rollback:
        raise HTTPException(status_code=400, detail="rollback_required requires prepare_rollback")

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
        "source_finding_id": target_finding.id if target_finding else "",
        "source_cve": target_finding.cve if target_finding else "",
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
            "source_finding_id": target_finding.id if target_finding else "",
        },
    )
    return serialize_campaign(campaign)


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


@app.post("/api/admin/campaigns/{campaign_id}/deploy")
def deploy_campaign(campaign_id: str, principal=Depends(require_operator), db: Session = Depends(get_db)):
    campaign = db.get(Campaign, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="campaign not found")
    if campaign.status != "draft":
        raise HTTPException(status_code=409, detail="campaign already deployed")

    selected = agents_for_ring(db, campaign, campaign.ring_percent)
    if not selected:
        raise HTTPException(status_code=409, detail="no agents matched campaign target")

    add_ring_jobs(db, campaign, selected, campaign.ring_percent)
    campaign.status = "deployed"
    db.commit()
    audit(
        db,
        principal["actor"],
        "campaign.deployed",
        "campaign",
        campaign.id,
        {"agents": len(selected), "ring_percent": campaign.ring_percent},
    )
    return {
        "ok": True,
        "agents_selected": len(selected),
        "ring_percent": campaign.ring_percent,
        "campaign": serialize_campaign(campaign),
    }


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
    if body.target_percent <= campaign.ring_percent:
        raise HTTPException(status_code=400, detail="target ring must be greater than current ring")
    if campaign.action == "activate_agent_update" and principal.get("role") != "admin":
        raise HTTPException(status_code=403, detail="admin role required to advance agent update rollout")

    health = campaign_health(campaign)
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
