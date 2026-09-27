import hashlib
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

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from .database import SessionLocal, get_db
from .models import AdminSession, AdminUser, Agent, AuditEvent, Campaign, IntegrationState, PatchJob, VulnerabilityFinding
from .schemas import CampaignCreate, HeartbeatRequest, JobResultRequest, JobRetryRequest, LeaseRenewRequest, LoginRequest, PasswordChangeRequest, RegisterRequest, RegisterResponse, RingAdvance, RollbackRequest, TagUpdate, UserCreateRequest, UserUpdateRequest, VulnerabilityImportRequest, VulnerabilityStatusUpdate
from .security import create_session, hash_token, new_token, password_hash, password_needs_rehash, password_verify, require_admin, require_enrollment, require_operator, require_viewer, revoke_session, validate_password_strength, validate_role, validate_username
from .greenbone import fetch_findings as fetch_greenbone_findings
from .greenbone import get_config as get_greenbone_config
from .greenbone import public_config as public_greenbone_config

app = FastAPI(title="Be Safe Patch Manager", version="0.9.0")
STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def _seconds_setting(name: str, default: int, minimum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, value)


def _bool_setting(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


JOB_CLAIM_LEASE_SECONDS = _seconds_setting("JOB_CLAIM_LEASE_SECONDS", 300, 60)
JOB_RUNNING_LEASE_SECONDS = _seconds_setting("JOB_RUNNING_LEASE_SECONDS", 7200, 300)
AGENT_MTLS_REQUIRED = _bool_setting("AGENT_MTLS_REQUIRED", False)
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
        "first_seen": v.first_seen.isoformat() if v.first_seen else None,
        "last_seen": v.last_seen.isoformat() if v.last_seen else None,
        "resolved_at": v.resolved_at.isoformat() if v.resolved_at else None,
    }



GREENBONE_SYNC_LOCK = threading.Lock()
GREENBONE_STOP = threading.Event()


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
        }
        state.status = "ok"
        state.last_success_at = now()
        state.last_error = ""
        state.details_json = dump(details)
        db.commit()
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


def greenbone_worker():
    config = get_greenbone_config()
    if not config.enabled:
        return
    delay = 10
    while not GREENBONE_STOP.wait(delay):
        try:
            run_greenbone_sync()
        except Exception:
            pass
        delay = get_greenbone_config().interval_seconds


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

    return {
        "status": "passed",
        "reason": "fresh heartbeat received with no patch regression",
        "baseline_pending": baseline_pending,
        "current_pending": agent.pending_updates,
        "baseline_critical": baseline_critical,
        "current_critical": agent.critical_updates,
    }


def ring_bucket(agent_id: str) -> int:
    return int(hashlib.sha256(agent_id.encode()).hexdigest()[:8], 16) % 10000


def campaign_ring_jobs(c: Campaign):
    marked = [
        job for job in c.jobs
        if job.action in {"scan_updates", "install_updates"}
        and int(load(job.payload_json, {}).get("_ring_percent", -1)) == int(c.ring_percent)
    ]
    return marked if marked else list(c.jobs)



def campaign_health(c: Campaign):
    jobs = campaign_ring_jobs(c)
    counts = {"pending": 0, "claimed": 0, "running": 0, "stalled": 0, "success": 0, "failed": 0, "skipped": 0}
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

    active = counts["pending"] + counts["claimed"] + counts["running"] + counts["stalled"]
    terminal = counts["success"] + counts["failed"] + counts["skipped"]
    success_rate = round((counts["success"] / terminal * 100), 1) if terminal else 0.0
    validation_blocked = validations["failed"] > 0 or validations["waiting"] > 0
    ready = (
        bool(jobs)
        and active == 0
        and terminal == len(jobs)
        and success_rate >= 90.0
        and not validation_blocked
    )

    if not jobs:
        reason = "no jobs in current ring"
    elif counts["stalled"]:
        reason = "current ring has stalled jobs"
    elif active:
        reason = "current ring still has active jobs"
    elif terminal != len(jobs):
        reason = "current ring has non-terminal jobs"
    elif success_rate < 90.0:
        reason = "success rate below 90%"
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
        "validation": validations,
        "validation_details": validation_details[:20],
        "ready": ready,
        "reason": reason,
    }


def serialize_campaign(c: Campaign):
    counts = {"pending": 0, "claimed": 0, "running": 0, "success": 0, "failed": 0, "skipped": 0}
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
    return {"status": "ok", "time": now().isoformat()}


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


@app.post("/api/agent/{agent_id}/heartbeat")
def heartbeat(
    agent_id: str,
    body: HeartbeatRequest,
    x_agent_token: str | None = Header(default=None),
    x_client_cert_fingerprint: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    agent = get_agent(db, agent_id, x_agent_token, x_client_cert_fingerprint)
    agent.last_seen = now()
    agent.inventory_json = dump(body.inventory)
    agent.patch_scan_json = dump(body.patch_scan)
    agent.reboot_required = body.reboot_required
    agent.pending_updates = len(body.patch_scan)
    agent.critical_updates = sum(1 for x in body.patch_scan if str(x.get("severity", "")).lower() in {"critical", "important", "security"})
    db.commit()
    return {"ok": True}


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

    for job in jobs:
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
    }


@app.get("/api/admin/agents")
def list_agents(_=Depends(require_viewer), db: Session = Depends(get_db)):
    return [serialize_agent(a) for a in db.query(Agent).order_by(Agent.hostname.asc()).all()]


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


@app.get("/api/admin/vulnerabilities")
def list_vulnerabilities(
    status: str | None = None,
    severity: str | None = None,
    agent_id: str | None = None,
    _=Depends(require_viewer),
    db: Session = Depends(get_db),
):
    q = db.query(VulnerabilityFinding).order_by(
        VulnerabilityFinding.cvss.desc(),
        VulnerabilityFinding.last_seen.desc(),
    )
    if status:
        q = q.filter(VulnerabilityFinding.status == status.lower())
    if severity:
        q = q.filter(VulnerabilityFinding.severity == severity.lower())
    if agent_id:
        q = q.filter(VulnerabilityFinding.agent_id == agent_id)
    return [serialize_vulnerability(item) for item in q.limit(1000).all()]


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



@app.get("/api/admin/campaigns")
def list_campaigns(_=Depends(require_viewer), db: Session = Depends(get_db)):
    campaigns = db.query(Campaign).order_by(Campaign.created_at.desc()).all()
    return [serialize_campaign(c) for c in campaigns]


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
    for agent in db.query(Agent).all():
        if target_agent_id and agent.id != target_agent_id:
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

    health = campaign_health(campaign)
    if not health["ready"] and not body.override_health_gate:
        raise HTTPException(
            status_code=409,
            detail={"message": "health gate blocked ring advance", "health": health},
        )

    target_agents = agents_for_ring(db, campaign, body.target_percent)
    existing_agent_ids = {job.agent_id for job in campaign.jobs}
    new_agents = [agent for agent in target_agents if agent.id not in existing_agent_ids]

    previous_ring = campaign.ring_percent
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
