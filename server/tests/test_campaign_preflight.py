import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

TEST_DB = Path(__file__).resolve().parent / "test-campaign-preflight.db"
TEST_DB.unlink(missing_ok=True)
SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "P" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"
os.environ["THREAT_INTEL_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app import main
from app.models import Agent, Campaign, CampaignApproval, CampaignPreflightSnapshot, PatchBlockRule


@pytest.fixture(autouse=True)
def clean_database(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(main, "AGENT_ENFORCE_COMPATIBILITY", True)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def make_agent(db, agent_id="a1", capabilities=None):
    capabilities = capabilities or [
        "job_leases_v1",
        "install_updates",
        "rollback_checkpoint_v1",
        "health_telemetry_v1",
    ]
    agent = Agent(
        id=agent_id,
        hostname=f"{agent_id}.local",
        os_family="windows",
        os_name="Windows Server 2022",
        token_hash=(agent_id + "-" + "x" * 64)[:64],
        tags='["tier0"]',
        last_seen=datetime.now(timezone.utc),
        inventory_json=main.dump({
            "agent": {
                "version": main.AGENT_MIN_VERSION,
                "protocol": main.AGENT_MIN_PROTOCOL,
                "capabilities": capabilities,
            }
        }),
    )
    db.add(agent)
    db.commit()
    return agent


def make_campaign(db, *, approval_required=False, payload_extra=None):
    payload = {
        "packages": ["KB5072198"],
        "prepare_rollback": True,
        "rollback_required": True,
        "health_policy": {"enabled": True, "required": True},
        "approval_required": approval_required,
        "maintenance_start": "",
        "maintenance_end": "",
        "maintenance_timezone": "America/Sao_Paulo",
        "maintenance_days": list(range(7)),
    }
    payload.update(payload_extra or {})
    campaign = Campaign(
        id="c1",
        name="Tier0 September",
        target_os="windows",
        target_tag="tier0",
        ring_percent=10,
        action="install_updates",
        payload_json=main.dump(payload),
        status="draft",
    )
    db.add(campaign)
    db.commit()
    return db.get(Campaign, "c1")


def check(report, key):
    return next(item for item in report["checks"] if item["key"] == key)


def test_preflight_ready_with_supported_agent(db):
    make_agent(db)
    campaign = make_campaign(db)
    report = main.campaign_preflight(db, campaign)

    assert report["deploy_allowed"] is True
    assert report["readiness"] in {"READY", "REVIEW"}
    assert check(report, "scope")["status"] == "passed"
    assert check(report, "agent_compatibility")["status"] == "passed"
    assert check(report, "patch_guard")["status"] == "passed"


def test_preflight_blocks_missing_approval(db):
    make_agent(db)
    campaign = make_campaign(db, approval_required=True)
    db.add(CampaignApproval(
        id="ap1",
        campaign_id=campaign.id,
        status="pending",
        request_reason="Tier0 change",
        requested_by="user:operator",
    ))
    db.commit()

    report = main.campaign_preflight(db, campaign)
    approval = check(report, "approval")

    assert report["readiness"] == "BLOCKED"
    assert report["deploy_allowed"] is False
    assert approval["blocking"] is True


def test_preflight_blocks_patch_guard(db):
    make_agent(db)
    campaign = make_campaign(db)
    db.add(PatchBlockRule(
        id="r1",
        name="Known regression",
        patch_ref="KB5072198",
        target_os="windows",
        target_tag="tier0",
        reason="pilot regression",
        enabled=True,
        created_by="user:admin",
        updated_by="user:admin",
    ))
    db.commit()

    report = main.campaign_preflight(db, campaign)
    guard = check(report, "patch_guard")

    assert report["deploy_allowed"] is False
    assert guard["status"] == "blocked"
    assert guard["details"]["blockers"][0]["matched_assets"] == 1


def test_preflight_blocks_incompatible_agent_when_enforced(db):
    make_agent(db, capabilities=["job_leases_v1", "install_updates"])
    campaign = make_campaign(db)

    report = main.campaign_preflight(db, campaign)
    compatibility = check(report, "agent_compatibility")

    assert compatibility["status"] == "blocked"
    assert compatibility["blocking"] is True
    assert report["deploy_allowed"] is False


def test_preflight_warns_on_stale_heartbeat(db):
    agent = make_agent(db)
    agent.last_seen = datetime.now(timezone.utc) - timedelta(hours=2)
    db.commit()
    campaign = make_campaign(db)

    report = main.campaign_preflight(db, campaign)
    heartbeat = check(report, "heartbeat")

    assert heartbeat["status"] == "warning"
    assert heartbeat["blocking"] is False
    assert report["readiness"] == "REVIEW"



def test_preflight_snapshot_is_immutable_hashed_evidence(db):
    make_agent(db)
    campaign = make_campaign(db)
    result = main.campaign_preflight(db, campaign)

    snapshot = main.persist_campaign_preflight_snapshot(
        db, campaign, result, "user:operator", "manual"
    )

    assert db.query(CampaignPreflightSnapshot).count() == 1
    assert snapshot.readiness == result["readiness"]
    assert snapshot.actor == "user:operator"
    assert snapshot.source == "manual"
    assert len(snapshot.result_sha256) == 64
    assert main.load(snapshot.result_json, {})["campaign_id"] == campaign.id


def test_preflight_drift_detects_degradation():
    previous = {
        "checks": [
            {"key": "heartbeat", "label": "Agent freshness", "status": "passed", "message": "recent"},
            {"key": "patch_guard", "label": "Patch Guard", "status": "passed", "message": "clear"},
        ]
    }
    current = {
        "checks": [
            {"key": "heartbeat", "label": "Agent freshness", "status": "warning", "message": "stale"},
            {"key": "patch_guard", "label": "Patch Guard", "status": "blocked", "message": "rule matched"},
        ]
    }

    drift = main.campaign_preflight_drift(previous, current)

    assert drift["status"] == "DEGRADED"
    assert drift["degraded"] == 2
    assert {item["key"] for item in drift["changes"]} == {"heartbeat", "patch_guard"}


def test_preflight_drift_reports_unchanged():
    result = {
        "checks": [
            {"key": "scope", "label": "Target scope", "status": "passed", "message": "10 endpoints"}
        ]
    }

    drift = main.campaign_preflight_drift(result, result)

    assert drift["status"] == "UNCHANGED"
    assert drift["changed"] is False
    assert drift["changes"] == []


def test_deploy_attempt_persists_preflight_snapshot(db):
    make_agent(db)
    campaign = make_campaign(db)

    result = main.deploy_campaign(
        campaign.id,
        principal={"actor": "user:operator", "role": "operator"},
        db=db,
    )

    snapshots = db.query(CampaignPreflightSnapshot).filter(
        CampaignPreflightSnapshot.campaign_id == campaign.id
    ).all()
    assert len(snapshots) == 1
    assert snapshots[0].source == "deploy_attempt"
    assert result["preflight_snapshot"]["id"] == snapshots[0].id
    assert result["preflight_drift"]["status"] == "NO_BASELINE"



def test_campaign_evidence_pack_hashes_sections_and_pack(db):
    make_agent(db)
    campaign = make_campaign(db)

    main.deploy_campaign(
        campaign.id,
        principal={"actor": "user:operator", "role": "operator"},
        db=db,
    )

    pack = main.campaign_evidence_pack(db, campaign)

    assert pack["schema"] == "be-safe-campaign-evidence-pack/v1"
    assert pack["summary"]["jobs"] == 1
    assert pack["summary"]["preflight_snapshots"] == 1
    assert len(pack["manifest"]["pack_sha256"]) == 64
    assert set(pack["manifest"]["section_hashes"]) == {
        "campaign",
        "approval",
        "preflight_snapshots",
        "ring_decisions",
        "jobs",
        "freeze_override",
        "audit_events",
    }

    for key, value in pack["sections"].items():
        assert pack["manifest"]["section_hashes"][key] == main._evidence_sha256(value)

    content = {key: value for key, value in pack.items() if key != "manifest"}
    assert pack["manifest"]["pack_sha256"] == main._evidence_sha256(content)


def test_campaign_evidence_pack_preserves_job_health_and_rollback_evidence(db):
    make_agent(db)
    campaign = make_campaign(db)
    result = main.deploy_campaign(
        campaign.id,
        principal={"actor": "user:operator", "role": "operator"},
        db=db,
    )
    db.refresh(campaign)
    job = campaign.jobs[0]
    job.status = "success"
    job.started_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    job.finished_at = datetime.now(timezone.utc)
    job.result_json = main.dump({
        "validation": {"ok": True},
        "health_validation": {"ok": True, "issues": []},
        "rollback": {"checkpoint_id": "cp-123"},
    })
    db.commit()

    pack = main.campaign_evidence_pack(db, campaign)
    exported = pack["sections"]["jobs"][0]

    assert exported["status"] == "success"
    assert "validation" in exported
    assert "rollback" in exported
    assert exported["campaign_id"] == result["campaign"]["id"]
