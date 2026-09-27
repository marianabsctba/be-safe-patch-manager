import json
import os
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException


TEST_DB = Path(__file__).resolve().parent / "test-agent-activation-api.db"
TEST_DB.unlink(missing_ok=True)
SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "A" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app import main
from app.models import Agent, Campaign, PatchJob
from app.schemas import AgentUpdateActivationRequest, AgentUpdateQuarantineClearRequest


def fake_release():
    return {
        "manifest": {
            "schema": 2,
            "product": "be-safe-patch-agent",
            "version": "0.17.0",
            "protocol": 2,
            "capabilities": ["signed_update_activation_v1"],
            "generated_at": "2026-09-27T19:00:00+00:00",
            "source_commit": "c" * 40,
            "signing_key_id": "d" * 64,
            "artifact": {
                "filename": "be-safe-patch-agent-0.17.0.zip",
                "sha256": "e" * 64,
                "size_bytes": 1234,
            },
        },
        "signature": b"x" * 64,
        "artifact_path": Path("/tmp/fake-agent-release.zip"),
    }


@pytest.fixture(autouse=True)
def clean_database(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(main, "signed_agent_release", fake_release)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def seed_agent(db, *, os_family="linux", staged_version="0.17.0", capability=True):
    caps = ["scan_updates", "job_leases_v1"]
    if capability:
        caps.extend(["signed_update_activation_v1", "signed_update_quarantine_v1"])
    agent = Agent(
        id="activation-agent",
        hostname="activation-host",
        os_family=os_family,
        os_name="Linux" if os_family == "linux" else "Windows",
        token_hash="a" * 64,
        last_seen=main.now(),
        inventory_json=json.dumps({
            "agent": {
                "version": "0.16.0",
                "protocol": 2,
                "capabilities": caps,
            },
            "update": {
                "status": "staged",
                "staged_version": staged_version,
                "artifact_sha256": "e" * 64,
                "source_commit": "c" * 40,
                "signing_key_id": "d" * 64,
            },
            "activation": {
                "status": "idle",
            },
        }),
        patch_scan_json="[]",
    )
    db.add(agent)
    db.commit()
    return agent


def request(version="0.17.0"):
    return AgentUpdateActivationRequest(
        expected_version=version,
        reason="janela de teste controlado",
        acknowledge_risk=True,
    )


def test_admin_can_queue_linux_activation(db):
    agent = seed_agent(db)

    result = main.approve_agent_update_activation(
        agent.id,
        request(),
        principal={"actor": "user:admin", "role": "admin"},
        db=db,
    )

    job = db.query(PatchJob).one()
    campaign = db.query(Campaign).one()
    assert result["ok"] is True
    assert job.action == "activate_agent_update"
    assert job.status == "pending"
    assert json.loads(job.payload_json)["expected_version"] == "0.17.0"
    assert campaign.action == "activate_agent_update"
    assert main.required_capabilities_for_job(job) == [
        "job_leases_v1",
        "signed_update_activation_v1",
    ]


def test_activation_requires_explicit_risk_acknowledgement(db):
    agent = seed_agent(db)
    body = request()
    body.acknowledge_risk = False

    with pytest.raises(HTTPException) as exc:
        main.approve_agent_update_activation(
            agent.id,
            body,
            principal={"actor": "user:admin", "role": "admin"},
            db=db,
        )
    assert exc.value.status_code == 400


def test_windows_activation_is_rejected_in_v015(db):
    agent = seed_agent(db, os_family="windows")

    with pytest.raises(HTTPException) as exc:
        main.approve_agent_update_activation(
            agent.id,
            request(),
            principal={"actor": "user:admin", "role": "admin"},
            db=db,
        )
    assert exc.value.status_code == 409
    assert "only on Linux" in str(exc.value.detail)


def test_staged_version_must_match_approval(db):
    agent = seed_agent(db, staged_version="0.16.1")

    with pytest.raises(HTTPException) as exc:
        main.approve_agent_update_activation(
            agent.id,
            request("0.17.0"),
            principal={"actor": "user:admin", "role": "admin"},
            db=db,
        )
    assert exc.value.status_code == 409


def test_agent_must_advertise_activation_capability(db):
    agent = seed_agent(db, capability=False)

    with pytest.raises(HTTPException) as exc:
        main.approve_agent_update_activation(
            agent.id,
            request(),
            principal={"actor": "user:admin", "role": "admin"},
            db=db,
        )
    assert exc.value.status_code == 409
    assert "does not support" in str(exc.value.detail)


def test_active_execution_blocks_agent_activation(db):
    agent = seed_agent(db)
    campaign = Campaign(
        id="busy-campaign",
        name="Busy",
        target_os="linux",
        ring_percent=100,
        action="scan_updates",
        status="deployed",
    )
    job = PatchJob(
        id="busy-job",
        campaign=campaign,
        agent=agent,
        action="scan_updates",
        status="running",
    )
    db.add_all([campaign, job])
    db.commit()

    with pytest.raises(HTTPException) as exc:
        main.approve_agent_update_activation(
            agent.id,
            request(),
            principal={"actor": "user:admin", "role": "admin"},
            db=db,
        )
    assert exc.value.status_code == 409
    assert "active execution" in str(exc.value.detail)



def quarantine_request(version="0.17.0"):
    return AgentUpdateQuarantineClearRequest(
        expected_version=version,
        reason="reteste aprovado após correção",
        acknowledge_risk=True,
    )


def test_watchdog_rollback_blocks_normal_activation(db):
    agent = seed_agent(db)
    inventory = json.loads(agent.inventory_json)
    inventory["activation"] = {
        "status": "rolled_back",
        "previous_version": "0.16.0",
        "target_version": "0.17.0",
        "rollback_reason": "startup_attempt_limit",
    }
    agent.inventory_json = json.dumps(inventory)
    db.commit()

    with pytest.raises(HTTPException) as exc:
        main.approve_agent_update_activation(
            agent.id,
            request(),
            principal={"actor": "user:admin", "role": "admin"},
            db=db,
        )
    assert exc.value.status_code == 409
    assert "quarantined" in str(exc.value.detail)


def test_admin_can_queue_quarantine_clear(db):
    agent = seed_agent(db)
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
    db.commit()

    result = main.clear_agent_update_quarantine(
        agent.id,
        quarantine_request(),
        principal={"actor": "user:admin", "role": "admin"},
        db=db,
    )

    job = db.query(PatchJob).one()
    assert result["ok"] is True
    assert job.action == "clear_agent_update_quarantine"
    assert main.required_capabilities_for_job(job) == [
        "job_leases_v1",
        "signed_update_quarantine_v1",
    ]


def test_quarantine_clear_requires_matching_rolled_back_version(db):
    agent = seed_agent(db)
    inventory = json.loads(agent.inventory_json)
    inventory["update"] = {
        "status": "quarantined",
        "staged_version": "0.17.0",
        "quarantined_version": "0.17.0",
    }
    inventory["activation"] = {
        "status": "rolled_back",
        "previous_version": "0.16.0",
        "target_version": "0.17.1",
    }
    agent.inventory_json = json.dumps(inventory)
    db.commit()

    with pytest.raises(HTTPException) as exc:
        main.clear_agent_update_quarantine(
            agent.id,
            quarantine_request(),
            principal={"actor": "user:admin", "role": "admin"},
            db=db,
        )
    assert exc.value.status_code == 409
