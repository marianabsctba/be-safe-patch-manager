import json
import os
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi import HTTPException


TEST_DB = Path(__file__).resolve().parent / "test-agent-update-rollout.db"
TEST_DB.unlink(missing_ok=True)
SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "R" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app import main
from app.models import Agent, PatchJob
from app.schemas import AgentUpdateRolloutCreate, RingAdvance


@pytest.fixture(autouse=True)
def clean_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def staged_inventory(version="0.17.0"):
    return {
        "agent": {
            "version": "0.16.0",
            "protocol": 2,
            "capabilities": [
                "scan_updates",
                "job_leases_v1",
                "signed_update_staging_v1",
                "signed_update_activation_v1",
                "signed_update_quarantine_v1",
            ],
        },
        "update": {
            "status": "staged",
            "staged_version": version,
        },
        "activation": {
            "status": "idle",
        },
    }


def add_agent(db, index, *, tag="pilot", staged=True, version="0.17.0"):
    inventory = staged_inventory(version)
    if not staged:
        inventory["update"] = {"status": "current"}
    agent = Agent(
        id=f"rollout-agent-{index:02d}",
        hostname=f"rollout-host-{index:02d}",
        os_family="linux",
        os_name="Linux",
        os_version="test",
        arch="x86_64",
        ip_address=f"10.0.0.{index + 10}",
        tags=json.dumps([tag]),
        token_hash=(f"{index:064x}")[-64:],
        last_seen=main.now(),
        inventory_json=json.dumps(inventory),
        patch_scan_json="[]",
    )
    db.add(agent)
    db.commit()
    return agent


def rollout_request(ring=10):
    return AgentUpdateRolloutCreate(
        name="Agent 0.17 pilot",
        description="rollout controlado do agente",
        target_tag="pilot",
        ring_percent=ring,
        expected_version="0.17.0",
        reason="janela controlada de atualização",
        acknowledge_risk=True,
    )


def seed_fleet(db, count=10):
    return [add_agent(db, i) for i in range(count)]


def commit_activation(db, job):
    finished = main.now()
    job.status = "success"
    job.started_at = finished - timedelta(seconds=5)
    job.finished_at = finished
    agent = job.agent
    inventory = json.loads(agent.inventory_json)
    inventory["agent"]["version"] = "0.17.0"
    inventory["update"] = {
        "status": "activated",
        "active_version": "0.17.0",
    }
    inventory["activation"] = {
        "status": "committed",
        "previous_version": "0.16.0",
        "target_version": "0.17.0",
        "confirmed_version": "0.17.0",
        "committed_at": (finished + timedelta(seconds=2)).isoformat(),
    }
    agent.inventory_json = json.dumps(inventory)
    agent.last_seen = finished + timedelta(seconds=3)
    db.commit()


def rollback_activation(db, job):
    finished = main.now()
    job.status = "success"
    job.started_at = finished - timedelta(seconds=5)
    job.finished_at = finished
    agent = job.agent
    inventory = json.loads(agent.inventory_json)
    inventory["update"] = {
        "status": "quarantined",
        "staged_version": "0.17.0",
        "quarantined_version": "0.17.0",
    }
    inventory["activation"] = {
        "status": "rolled_back",
        "previous_version": "0.16.0",
        "target_version": "0.17.0",
        "rollback_reason": "startup_attempt_limit",
    }
    agent.inventory_json = json.dumps(inventory)
    agent.last_seen = finished + timedelta(seconds=3)
    db.commit()


def test_rollout_snapshots_fleet_and_deploys_ten_percent(db):
    seed_fleet(db, 10)

    result = main.create_agent_update_rollout(
        rollout_request(10),
        principal={"actor": "user:admin", "role": "admin"},
        db=db,
    )

    campaign = result["campaign"]
    jobs = db.query(PatchJob).all()

    assert result["eligible_agents"] == 10
    assert result["initial_agents"] == 1
    assert campaign["ring_percent"] == 10
    assert campaign["action"] == "activate_agent_update"
    assert len(campaign["payload"]["target_agent_ids"]) == 10
    assert len(jobs) == 1
    assert jobs[0].action == "activate_agent_update"
    assert json.loads(jobs[0].payload_json)["_ring_percent"] == 10


def test_agent_rollout_health_waits_for_committed_heartbeat(db):
    seed_fleet(db, 10)
    created = main.create_agent_update_rollout(
        rollout_request(),
        principal={"actor": "user:admin", "role": "admin"},
        db=db,
    )
    campaign = db.get(main.Campaign, created["campaign"]["id"])
    job = campaign.jobs[0]
    job.status = "success"
    job.finished_at = main.now()
    db.commit()

    waiting = main.campaign_health(campaign)
    assert waiting["ready"] is False
    assert waiting["validation"]["waiting"] == 1

    commit_activation(db, job)
    db.refresh(campaign)

    healthy = main.campaign_health(campaign)
    assert healthy["ready"] is True
    assert healthy["validation"]["passed"] == 1


def test_healthy_ten_percent_can_advance_to_thirty(db):
    seed_fleet(db, 10)
    created = main.create_agent_update_rollout(
        rollout_request(),
        principal={"actor": "user:admin", "role": "admin"},
        db=db,
    )
    campaign = db.get(main.Campaign, created["campaign"]["id"])
    commit_activation(db, campaign.jobs[0])
    db.refresh(campaign)

    result = main.advance_campaign(
        campaign.id,
        RingAdvance(target_percent=30, override_health_gate=False),
        principal={"actor": "user:admin", "role": "admin"},
        db=db,
    )

    assert result["from_ring"] == 10
    assert result["to_ring"] == 30
    assert result["new_agents"] == 2
    assert db.query(PatchJob).count() == 3


def test_watchdog_rollback_hard_stops_ring_even_with_override(db):
    seed_fleet(db, 10)
    created = main.create_agent_update_rollout(
        rollout_request(),
        principal={"actor": "user:admin", "role": "admin"},
        db=db,
    )
    campaign = db.get(main.Campaign, created["campaign"]["id"])
    rollback_activation(db, campaign.jobs[0])
    db.refresh(campaign)

    health = main.campaign_health(campaign)
    assert health["ready"] is False
    assert health["validation"]["failed"] == 1

    with pytest.raises(HTTPException) as blocked:
        main.advance_campaign(
            campaign.id,
            RingAdvance(target_percent=30, override_health_gate=False),
            principal={"actor": "user:admin", "role": "admin"},
            db=db,
        )
    assert blocked.value.status_code == 409

    with pytest.raises(HTTPException) as override:
        main.advance_campaign(
            campaign.id,
            RingAdvance(target_percent=30, override_health_gate=True),
            principal={"actor": "user:admin", "role": "admin"},
            db=db,
        )
    assert override.value.status_code == 400
    assert "override is disabled" in str(override.value.detail)


def test_rollout_snapshot_does_not_expand_when_new_agent_appears(db):
    seed_fleet(db, 10)
    created = main.create_agent_update_rollout(
        rollout_request(),
        principal={"actor": "user:admin", "role": "admin"},
        db=db,
    )
    campaign = db.get(main.Campaign, created["campaign"]["id"])
    snapshot = set(json.loads(campaign.payload_json)["target_agent_ids"])

    add_agent(db, 99)
    assert db.query(Agent).count() == 11

    commit_activation(db, campaign.jobs[0])
    db.refresh(campaign)
    main.advance_campaign(
        campaign.id,
        RingAdvance(target_percent=100, override_health_gate=False),
        principal={"actor": "user:admin", "role": "admin"},
        db=db,
    )

    job_agent_ids = {job.agent_id for job in db.query(PatchJob).all()}
    assert job_agent_ids == snapshot
    assert "rollout-agent-99" not in job_agent_ids


def test_quarantined_agent_is_not_eligible_for_new_rollout(db):
    agent = add_agent(db, 1)
    inventory = json.loads(agent.inventory_json)
    inventory["update"] = {
        "status": "quarantined",
        "staged_version": "0.17.0",
        "quarantined_version": "0.17.0",
    }
    inventory["activation"] = {
        "status": "rolled_back",
        "previous_version": "0.16.0",
        "target_version": "0.17.0",
    }
    agent.inventory_json = json.dumps(inventory)
    db.commit()

    with pytest.raises(HTTPException) as exc:
        main.create_agent_update_rollout(
            rollout_request(),
            principal={"actor": "user:admin", "role": "admin"},
            db=db,
        )

    assert exc.value.status_code == 409
    assert exc.value.detail["skipped"]["not_staged"] == 1



def test_agent_rollout_requires_one_hundred_percent_success(db):
    seed_fleet(db, 10)
    created = main.create_agent_update_rollout(
        rollout_request(100),
        principal={"actor": "user:admin", "role": "admin"},
        db=db,
    )
    campaign = db.get(main.Campaign, created["campaign"]["id"])
    assert len(campaign.jobs) == 10

    for job in campaign.jobs[:9]:
        commit_activation(db, job)

    failed = campaign.jobs[9]
    failed.status = "failed"
    failed.started_at = main.now() - timedelta(seconds=5)
    failed.finished_at = main.now()
    failed.error = "simulated activation failure"
    db.commit()
    db.refresh(campaign)

    health = main.campaign_health(campaign)

    assert health["success_rate"] == 90.0
    assert health["required_success_rate"] == 100.0
    assert health["ready"] is False
    assert health["reason"] == "success rate below required threshold"


def test_agent_activation_confirmation_timeout_fails_ring(db, monkeypatch):
    seed_fleet(db, 10)
    created = main.create_agent_update_rollout(
        rollout_request(),
        principal={"actor": "user:admin", "role": "admin"},
        db=db,
    )
    campaign = db.get(main.Campaign, created["campaign"]["id"])
    job = campaign.jobs[0]

    monkeypatch.setattr(main, "AGENT_ACTIVATION_CONFIRM_TIMEOUT_SECONDS", 60)
    job.status = "success"
    job.started_at = main.now() - timedelta(seconds=70)
    job.finished_at = main.now() - timedelta(seconds=65)
    inventory = json.loads(job.agent.inventory_json)
    inventory["activation"] = {
        "status": "pending",
        "previous_version": "0.16.0",
        "target_version": "0.17.0",
    }
    job.agent.inventory_json = json.dumps(inventory)
    job.agent.last_seen = main.now() - timedelta(seconds=64)
    db.commit()
    db.refresh(campaign)

    health = main.campaign_health(campaign)

    assert health["ready"] is False
    assert health["validation"]["failed"] == 1
    assert health["validation_details"][0]["reason"] == "agent activation confirmation timed out"


def test_operator_cannot_advance_agent_update_rollout(db):
    seed_fleet(db, 10)
    created = main.create_agent_update_rollout(
        rollout_request(),
        principal={"actor": "user:admin", "role": "admin"},
        db=db,
    )
    campaign = db.get(main.Campaign, created["campaign"]["id"])
    commit_activation(db, campaign.jobs[0])
    db.refresh(campaign)

    with pytest.raises(HTTPException) as exc:
        main.advance_campaign(
            campaign.id,
            RingAdvance(target_percent=30, override_health_gate=False),
            principal={"actor": "user:operator", "role": "operator"},
            db=db,
        )

    assert exc.value.status_code == 403
    assert "admin role required" in str(exc.value.detail)
