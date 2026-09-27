import json
import os
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi import HTTPException


TEST_DB = Path(__file__).resolve().parent / "test-agent-update-authorization.db"
TEST_DB.unlink(missing_ok=True)
SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "Z" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app import main
from app.models import Agent, Campaign, PatchJob
from app.schemas import AgentUpdateActivationRequest, AgentUpdateRolloutCreate
from app.security import hash_token


BINDING = {
    "version": "0.17.0",
    "artifact_sha256": "e" * 64,
    "source_commit": "c" * 40,
    "signing_key_id": "d" * 64,
}


def release(binding=None):
    binding = binding or BINDING
    return {
        "manifest": {
            "schema": 2,
            "product": "be-safe-patch-agent",
            "version": binding["version"],
            "protocol": 2,
            "capabilities": ["signed_update_activation_v1"],
            "generated_at": "2026-09-27T19:00:00+00:00",
            "source_commit": binding["source_commit"],
            "signing_key_id": binding["signing_key_id"],
            "artifact": {
                "filename": f"be-safe-patch-agent-{binding['version']}.zip",
                "sha256": binding["artifact_sha256"],
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
    monkeypatch.setattr(main, "signed_agent_release", lambda: release())
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def staged_inventory(binding=None):
    binding = binding or BINDING
    return {
        "agent": {
            "version": "0.16.0",
            "protocol": 2,
            "capabilities": [
                "job_leases_v1",
                "signed_update_staging_v1",
                "signed_update_activation_v1",
            ],
        },
        "update": {
            "status": "staged",
            "staged_version": binding["version"],
            "artifact_sha256": binding["artifact_sha256"],
            "source_commit": binding["source_commit"],
            "signing_key_id": binding["signing_key_id"],
        },
        "activation": {"status": "idle"},
    }


def seed_agent(db, *, last_seen=None, binding=None):
    token = "authorization-token-" + ("x" * 32)
    agent = Agent(
        id="authorization-agent",
        hostname="authorization-host",
        os_family="linux",
        os_name="Linux",
        token_hash=hash_token(token),
        last_seen=last_seen if last_seen is not None else main.now(),
        inventory_json=json.dumps(staged_inventory(binding)),
        patch_scan_json="[]",
        tags=json.dumps(["pilot"]),
    )
    db.add(agent)
    db.commit()
    return agent, token


def activation_payload(*, expires_at, binding=None):
    binding = binding or BINDING
    return {
        "expected_version": binding["version"],
        "approved_reason": "janela controlada",
        "approved_by": "user:admin",
        "activation_platform": "linux",
        "approved_at": (expires_at - timedelta(minutes=5)).isoformat(),
        "approval_expires_at": expires_at.isoformat(),
        "release_binding": binding,
    }


def seed_activation_job(db, agent, *, expires_at, binding=None):
    payload = activation_payload(expires_at=expires_at, binding=binding)
    campaign = Campaign(
        id="authorization-campaign",
        name="Authorization",
        target_os="linux",
        ring_percent=100,
        action="activate_agent_update",
        payload_json=json.dumps(payload),
        status="deployed",
    )
    job = PatchJob(
        id="authorization-job",
        campaign=campaign,
        agent=agent,
        action="activate_agent_update",
        payload_json=json.dumps(payload),
        status="pending",
    )
    db.add_all([campaign, job])
    db.commit()
    return job


def test_expired_activation_is_skipped_before_claim_token(db):
    agent, token = seed_agent(db)
    job = seed_activation_job(
        db,
        agent,
        expires_at=main.now() - timedelta(seconds=1),
    )

    claimed = main.poll_jobs(agent.id, x_agent_token=token, db=db)

    assert claimed == []
    db.refresh(job)
    assert job.status == "skipped"
    assert job.claim_token_hash == ""
    assert job.claimed_at is None
    assert "approval_expired" in job.error


def test_release_change_invalidates_pending_activation(db, monkeypatch):
    agent, token = seed_agent(db)
    job = seed_activation_job(
        db,
        agent,
        expires_at=main.now() + timedelta(minutes=10),
    )

    changed = {
        **BINDING,
        "source_commit": "f" * 40,
    }
    monkeypatch.setattr(main, "signed_agent_release", lambda: release(changed))

    claimed = main.poll_jobs(agent.id, x_agent_token=token, db=db)

    assert claimed == []
    db.refresh(job)
    assert job.status == "skipped"
    assert "published_release_changed" in job.error


def test_staged_artifact_identity_drift_invalidates_activation(db):
    drifted = {
        **BINDING,
        "artifact_sha256": "a" * 64,
    }
    agent, token = seed_agent(db, binding=drifted)
    job = seed_activation_job(
        db,
        agent,
        expires_at=main.now() + timedelta(minutes=10),
        binding=BINDING,
    )

    claimed = main.poll_jobs(agent.id, x_agent_token=token, db=db)

    assert claimed == []
    db.refresh(job)
    assert job.status == "skipped"
    assert "artifact_sha256_mismatch" in job.error


def test_fresh_bound_activation_can_be_claimed(db):
    agent, token = seed_agent(db)
    job = seed_activation_job(
        db,
        agent,
        expires_at=main.now() + timedelta(minutes=10),
    )

    claimed = main.poll_jobs(agent.id, x_agent_token=token, db=db)

    assert len(claimed) == 1
    assert claimed[0]["id"] == job.id
    assert claimed[0]["action"] == "activate_agent_update"
    assert claimed[0]["claim_token"]


def test_stale_heartbeat_blocks_individual_activation_approval(db):
    agent, _ = seed_agent(
        db,
        last_seen=main.now() - timedelta(seconds=main.AGENT_UPDATE_MAX_HEARTBEAT_AGE_SECONDS + 1),
    )
    body = AgentUpdateActivationRequest(
        expected_version="0.17.0",
        reason="janela controlada de atualização",
        acknowledge_risk=True,
    )

    with pytest.raises(HTTPException) as exc:
        main.approve_agent_update_activation(
            agent.id,
            body,
            principal={"actor": "user:admin", "role": "admin"},
            db=db,
        )

    assert exc.value.status_code == 409
    assert "heartbeat is too old" in str(exc.value.detail)


def test_rollout_reports_stale_heartbeat_as_skipped(db):
    seed_agent(
        db,
        last_seen=main.now() - timedelta(seconds=main.AGENT_UPDATE_MAX_HEARTBEAT_AGE_SECONDS + 1),
    )
    body = AgentUpdateRolloutCreate(
        name="Agent rollout",
        target_tag="pilot",
        ring_percent=10,
        expected_version="0.17.0",
        reason="janela controlada de atualização",
        acknowledge_risk=True,
    )

    with pytest.raises(HTTPException) as exc:
        main.create_agent_update_rollout(
            body,
            principal={"actor": "user:admin", "role": "admin"},
            db=db,
        )

    assert exc.value.status_code == 409
    assert exc.value.detail["skipped"]["stale_heartbeat"] == 1


def test_individual_approval_carries_release_binding_and_expiry(db):
    agent, _ = seed_agent(db)
    body = AgentUpdateActivationRequest(
        expected_version="0.17.0",
        reason="janela controlada de atualização",
        acknowledge_risk=True,
    )

    result = main.approve_agent_update_activation(
        agent.id,
        body,
        principal={"actor": "user:admin", "role": "admin"},
        db=db,
    )

    payload = result["job"]["payload"]
    assert payload["release_binding"] == BINDING
    assert payload["approved_at"]
    assert payload["approval_expires_at"]
    assert main._approval_expiry(payload) > main.now()
