import json
import os
import sys
from pathlib import Path

import pytest


TEST_DB = Path(__file__).resolve().parent / "test-agent-compatibility.db"
TEST_DB.unlink(missing_ok=True)

SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "C" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"
os.environ["AGENT_ENFORCE_COMPATIBILITY"] = "false"

from app.database import Base, SessionLocal, engine
from app import main
from app.models import Agent, Campaign, PatchJob
from app.security import hash_token


@pytest.fixture(autouse=True)
def clean_database(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(main, "AGENT_ENFORCE_COMPATIBILITY", True)
    monkeypatch.setattr(main, "AGENT_MIN_VERSION", "0.13.0")
    monkeypatch.setattr(main, "AGENT_MIN_PROTOCOL", 2)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def runtime(version="0.13.0", protocol=2, capabilities=None):
    return {
        "agent": {
            "version": version,
            "protocol": protocol,
            "capabilities": capabilities if capabilities is not None else [
                "scan_updates",
                "install_updates",
                "job_leases_v1",
                "health_telemetry_v1",
                "rollback_checkpoint_v1",
                "rollback_restore_v1",
                "mtls_client_v1",
            ],
        }
    }


def seed(db, *, inventory=None, action="scan_updates", payload=None):
    token = "compat-token-" + ("x" * 32)
    agent = Agent(
        id="compat-agent",
        hostname="compat-host",
        os_family="linux",
        os_name="Linux",
        token_hash=hash_token(token),
        last_seen=main.now(),
        inventory_json=json.dumps(inventory or {}),
        patch_scan_json="[]",
    )
    campaign = Campaign(
        id="compat-campaign",
        name="Compatibility",
        target_os="linux",
        ring_percent=100,
        action=action,
        status="deployed",
        payload_json=json.dumps(payload or {}),
    )
    job = PatchJob(
        id="compat-job",
        campaign=campaign,
        agent=agent,
        action=action,
        payload_json=json.dumps(payload or {}),
        status="pending",
    )
    db.add_all([agent, campaign, job])
    db.commit()
    return agent, campaign, job, token


def test_version_comparison_is_semver_numeric():
    assert main.version_at_least("0.13.0", "0.13.0")
    assert main.version_at_least("0.13.10", "0.13.2")
    assert main.version_at_least("1.0.0", "0.99.99")
    assert not main.version_at_least("0.12.9", "0.13.0")
    assert not main.version_at_least("unknown", "0.13.0")


def test_supported_agent_reports_compatibility(db):
    agent, _, job, _ = seed(db, inventory=runtime())

    meta = main.agent_runtime_metadata(agent)
    compatibility = main.job_agent_compatibility(job, agent)

    assert meta["status"] == "supported"
    assert meta["version"] == "0.13.0"
    assert meta["protocol"] == 2
    assert compatibility["compatible"] is True
    assert compatibility["missing_capabilities"] == []


def test_outdated_agent_job_is_blocked_before_claim(db):
    agent, _, job, token = seed(db, inventory=runtime(version="0.12.9"))

    jobs = main.poll_jobs(agent.id, x_agent_token=token, db=db)

    assert jobs == []
    db.refresh(job)
    assert job.status == "blocked"
    assert "outdated" in job.error
    assert "version=0.12.9" in job.error
    assert job.claim_token_hash == ""


def test_missing_capability_blocks_advanced_install(db):
    capabilities = [
        "install_updates",
        "job_leases_v1",
        "rollback_checkpoint_v1",
    ]
    payload = {
        "prepare_rollback": True,
        "health_policy": {"enabled": True},
    }
    agent, _, job, token = seed(
        db,
        inventory=runtime(capabilities=capabilities),
        action="install_updates",
        payload=payload,
    )

    jobs = main.poll_jobs(agent.id, x_agent_token=token, db=db)

    assert jobs == []
    db.refresh(job)
    assert job.status == "blocked"
    assert "missing_capabilities" in job.error
    assert "health_telemetry_v1" in job.error


def test_unknown_agent_is_blocked_when_enforcement_is_enabled(db):
    agent, _, job, token = seed(db, inventory={})

    jobs = main.poll_jobs(agent.id, x_agent_token=token, db=db)

    assert jobs == []
    db.refresh(job)
    assert job.status == "blocked"
    assert "unknown" in job.error


def test_agent_upgrade_unblocks_compatibility_job(db):
    agent, _, job, token = seed(db, inventory=runtime(version="0.12.0"))
    assert main.poll_jobs(agent.id, x_agent_token=token, db=db) == []
    db.refresh(job)
    assert job.status == "blocked"

    agent.inventory_json = json.dumps(runtime(version="0.13.0"))
    db.commit()

    changed = main.reconcile_blocked_agent_jobs(db, agent)
    db.refresh(job)

    assert changed == 1
    assert job.status == "pending"
    assert job.error == ""

    claimed = main.poll_jobs(agent.id, x_agent_token=token, db=db)
    assert len(claimed) == 1
    assert claimed[0]["id"] == job.id
    assert claimed[0]["agent_compatibility"]["compatible"] is True


def test_observation_mode_does_not_block_legacy_agent(db, monkeypatch):
    monkeypatch.setattr(main, "AGENT_ENFORCE_COMPATIBILITY", False)
    agent, _, job, token = seed(db, inventory={})

    claimed = main.poll_jobs(agent.id, x_agent_token=token, db=db)

    assert len(claimed) == 1
    db.refresh(job)
    assert job.status == "claimed"


def test_campaign_health_explains_compatibility_block(db):
    agent, campaign, job, _ = seed(db, inventory=runtime(version="0.12.0"))
    job.status = "blocked"
    job.error = "agent compatibility blocked: outdated"
    db.commit()

    health = main.campaign_health(campaign)

    assert health["ready"] is False
    assert health["counts"]["blocked"] == 1
    assert health["reason"] == "current ring has compatibility-blocked jobs"
