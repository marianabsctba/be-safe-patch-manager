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
from app.models import Agent, Campaign, CampaignApproval, PatchBlockRule


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
