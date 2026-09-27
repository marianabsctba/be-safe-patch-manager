import hashlib
import math
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from .database import Base, engine, get_db
from .models import Agent, AuditEvent, Campaign, PatchJob
from .schemas import CampaignCreate, HeartbeatRequest, JobResultRequest, RegisterRequest, RegisterResponse, RingAdvance, TagUpdate
from .security import hash_token, new_token, require_admin, require_enrollment

Base.metadata.create_all(bind=engine)
app = FastAPI(title="Be Safe Patch Manager", version="0.2.0")
STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


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


def get_agent(db: Session, agent_id: str, token: str | None) -> Agent:
    if not token:
        raise HTTPException(status_code=401, detail="missing agent token")
    agent = db.get(Agent, agent_id)
    if not agent or agent.token_hash != hash_token(token):
        raise HTTPException(status_code=401, detail="invalid agent credentials")
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
        "last_seen": a.last_seen.isoformat() if a.last_seen else None,
        "reboot_required": a.reboot_required,
        "pending_updates": a.pending_updates,
        "critical_updates": a.critical_updates,
        "inventory": load(a.inventory_json, {}),
        "patch_scan": load(a.patch_scan_json, []),
        "created_at": a.created_at.isoformat(),
    }



def ring_bucket(agent_id: str) -> int:
    return int(hashlib.sha256(agent_id.encode()).hexdigest()[:8], 16) % 10000


def campaign_ring_jobs(c: Campaign):
    marked = [
        job for job in c.jobs
        if int(load(job.payload_json, {}).get("_ring_percent", -1)) == int(c.ring_percent)
    ]
    return marked if marked else list(c.jobs)


def campaign_health(c: Campaign):
    jobs = campaign_ring_jobs(c)
    counts = {"pending": 0, "claimed": 0, "running": 0, "success": 0, "failed": 0, "skipped": 0}
    for job in jobs:
        counts[job.status] = counts.get(job.status, 0) + 1

    active = counts["pending"] + counts["claimed"] + counts["running"]
    terminal = counts["success"] + counts["failed"] + counts["skipped"]
    success_rate = round((counts["success"] / terminal * 100), 1) if terminal else 0.0
    ready = bool(jobs) and active == 0 and terminal == len(jobs) and success_rate >= 90.0

    if not jobs:
        reason = "no jobs in current ring"
    elif active:
        reason = "current ring still has active jobs"
    elif terminal != len(jobs):
        reason = "current ring has non-terminal jobs"
    elif success_rate < 90.0:
        reason = "success rate below 90%"
    else:
        reason = "healthy"

    return {
        "ring_percent": c.ring_percent,
        "jobs": len(jobs),
        "counts": counts,
        "active": active,
        "terminal": terminal,
        "success_rate": success_rate,
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


def serialize_job(j: PatchJob):
    return {
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
    }


@app.get("/")
def root():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health():
    return {"status": "ok", "time": now().isoformat()}


@app.post("/api/agent/register", response_model=RegisterResponse)
def register_agent(body: RegisterRequest, _=Depends(require_enrollment), db: Session = Depends(get_db)):
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
        last_seen=now(),
    )
    db.add(agent)
    db.commit()
    audit(db, f"agent:{agent_id}", "agent.registered", "agent", agent_id, {"hostname": body.hostname})
    return RegisterResponse(agent_id=agent_id, agent_token=raw_token)


@app.post("/api/agent/{agent_id}/heartbeat")
def heartbeat(agent_id: str, body: HeartbeatRequest, x_agent_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    agent = get_agent(db, agent_id, x_agent_token)
    agent.last_seen = now()
    agent.inventory_json = dump(body.inventory)
    agent.patch_scan_json = dump(body.patch_scan)
    agent.reboot_required = body.reboot_required
    agent.pending_updates = len(body.patch_scan)
    agent.critical_updates = sum(1 for x in body.patch_scan if str(x.get("severity", "")).lower() in {"critical", "important", "security"})
    db.commit()
    return {"ok": True}


@app.get("/api/agent/{agent_id}/jobs")
def poll_jobs(agent_id: str, x_agent_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    agent = get_agent(db, agent_id, x_agent_token)
    t = now()
    jobs = db.query(PatchJob).filter(PatchJob.agent_id == agent.id, PatchJob.status == "pending").order_by(PatchJob.created_at.asc()).all()
    ready = []
    for job in jobs:
        if job.not_before:
            nb = job.not_before
            if nb.tzinfo is None:
                nb = nb.replace(tzinfo=timezone.utc)
            if nb > t:
                continue
        job.status = "claimed"
        job.claimed_at = t
        ready.append(serialize_job(job))
        if len(ready) >= 1:
            break
    db.commit()
    return ready


@app.post("/api/agent/{agent_id}/jobs/{job_id}/result")
def job_result(agent_id: str, job_id: str, body: JobResultRequest, x_agent_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    agent = get_agent(db, agent_id, x_agent_token)
    job = db.get(PatchJob, job_id)
    if not job or job.agent_id != agent.id:
        raise HTTPException(status_code=404, detail="job not found")
    if body.status not in {"running", "success", "failed", "skipped"}:
        raise HTTPException(status_code=400, detail="invalid status")
    job.status = body.status
    job.result_json = dump(body.result)
    job.error = body.error
    if body.started_at:
        job.started_at = body.started_at
    elif body.status == "running" and not job.started_at:
        job.started_at = now()
    if body.finished_at:
        job.finished_at = body.finished_at
    elif body.status in {"success", "failed", "skipped"}:
        job.finished_at = now()
    db.commit()
    audit(db, f"agent:{agent.id}", f"job.{body.status}", "job", job.id, {"campaign_id": job.campaign_id, "error": body.error})
    return {"ok": True}


@app.get("/api/admin/summary")
def admin_summary(_=Depends(require_admin), db: Session = Depends(get_db)):
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
    }


@app.get("/api/admin/agents")
def list_agents(_=Depends(require_admin), db: Session = Depends(get_db)):
    return [serialize_agent(a) for a in db.query(Agent).order_by(Agent.hostname.asc()).all()]


@app.put("/api/admin/agents/{agent_id}/tags")
def update_tags(agent_id: str, body: TagUpdate, _=Depends(require_admin), db: Session = Depends(get_db)):
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    agent.tags = dump(sorted(set(body.tags)))
    db.commit()
    audit(db, "admin", "agent.tags.updated", "agent", agent_id, {"tags": body.tags})
    return serialize_agent(agent)


@app.get("/api/admin/campaigns")
def list_campaigns(_=Depends(require_admin), db: Session = Depends(get_db)):
    campaigns = db.query(Campaign).order_by(Campaign.created_at.desc()).all()
    return [serialize_campaign(c) for c in campaigns]


@app.post("/api/admin/campaigns")
def create_campaign(body: CampaignCreate, _=Depends(require_admin), db: Session = Depends(get_db)):
    if body.action not in {"scan_updates", "install_updates"}:
        raise HTTPException(status_code=400, detail="unsupported action")
    campaign = Campaign(
        id=str(uuid.uuid4()),
        name=body.name,
        description=body.description,
        target_os=body.target_os.lower(),
        target_tag=body.target_tag,
        ring_percent=body.ring_percent,
        action=body.action,
        payload_json=dump({**body.payload, "allow_reboot": body.allow_reboot}),
        not_before=body.not_before,
        allow_reboot=body.allow_reboot,
        status="draft",
    )
    db.add(campaign)
    db.commit()
    audit(db, "admin", "campaign.created", "campaign", campaign.id, {"name": campaign.name})
    return serialize_campaign(campaign)



def campaign_candidates(db: Session, campaign: Campaign):
    candidates = []
    for agent in db.query(Agent).all():
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
        payload = {**base_payload, "_ring_percent": ring_percent}
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
def deploy_campaign(campaign_id: str, _=Depends(require_admin), db: Session = Depends(get_db)):
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
        "admin",
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
    _=Depends(require_admin),
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
        "admin",
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


@app.get("/api/admin/jobs")
def list_jobs(campaign_id: str | None = None, _=Depends(require_admin), db: Session = Depends(get_db)):
    q = db.query(PatchJob).order_by(PatchJob.created_at.desc())
    if campaign_id:
        q = q.filter(PatchJob.campaign_id == campaign_id)
    return [serialize_job(j) for j in q.limit(500).all()]


@app.get("/api/admin/audit")
def list_audit(_=Depends(require_admin), db: Session = Depends(get_db)):
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
