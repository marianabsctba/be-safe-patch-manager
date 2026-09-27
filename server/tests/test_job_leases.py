import os
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi import HTTPException


SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

TEST_DB = Path(__file__).resolve().parent / "test-runtime.db"
TEST_DB.unlink(missing_ok=True)

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ADMIN_TOKEN"] = "A" * 48
os.environ["ENROLLMENT_TOKEN"] = "B" * 48
os.environ["GREENBONE_ENABLED"] = "false"
os.environ["JOB_CLAIM_LEASE_SECONDS"] = "300"
os.environ["JOB_RUNNING_LEASE_SECONDS"] = "7200"

from app.database import Base, SessionLocal, engine
from app.models import Agent, Campaign, PatchJob
from app.schemas import JobResultRequest, JobRetryRequest
from app.security import hash_token
from app import main


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


def seed_job(db, status="pending", lease_expires_at=None, claim_token=""):
    agent_token = "agent-token-" + ("x" * 32)
    agent = Agent(
        id="11111111-1111-1111-1111-111111111111",
        hostname="lab-linux-01",
        os_family="linux",
        os_name="Linux",
        token_hash=hash_token(agent_token),
        last_seen=main.now(),
    )
    campaign = Campaign(
        id="22222222-2222-2222-2222-222222222222",
        name="Lab",
        target_os="linux",
        ring_percent=100,
        action="scan_updates",
        status="deployed",
    )
    job = PatchJob(
        id="33333333-3333-3333-3333-333333333333",
        campaign=campaign,
        agent=agent,
        action="scan_updates",
        payload_json="{}",
        status=status,
        claimed_at=main.now() if status in {"claimed", "running"} else None,
        claim_token_hash=hash_token(claim_token) if claim_token else "",
        lease_expires_at=lease_expires_at,
        last_lease_at=main.now() if status in {"claimed", "running"} else None,
        attempt_count=1 if status in {"claimed", "running"} else 0,
    )
    db.add_all([agent, campaign, job])
    db.commit()
    return agent, campaign, job, agent_token


def test_poll_claims_job_once_and_uses_attempt_token(db):
    agent, _, job, agent_token = seed_job(db)

    first = main.poll_jobs(agent.id, x_agent_token=agent_token, db=db)
    second = main.poll_jobs(agent.id, x_agent_token=agent_token, db=db)

    assert len(first) == 1
    assert second == []
    assert first[0]["id"] == job.id
    assert first[0]["claim_token"]
    assert first[0]["claim_token"] != job.claim_token_hash

    db.refresh(job)
    assert job.status == "claimed"
    assert job.attempt_count == 1
    assert job.claim_token_hash == hash_token(first[0]["claim_token"])
    assert job.lease_expires_at is not None


def test_terminal_result_is_idempotent_but_conflicts_are_rejected(db):
    agent, _, job, agent_token = seed_job(db)
    claimed = main.poll_jobs(agent.id, x_agent_token=agent_token, db=db)[0]
    claim_token = claimed["claim_token"]

    running = JobResultRequest(status="running", claim_token=claim_token)
    main.job_result(agent.id, job.id, running, x_agent_token=agent_token, db=db)

    success = JobResultRequest(
        status="success",
        claim_token=claim_token,
        result={"updates": 3},
    )
    first = main.job_result(agent.id, job.id, success, x_agent_token=agent_token, db=db)
    repeated = main.job_result(agent.id, job.id, success, x_agent_token=agent_token, db=db)

    assert first == {"ok": True, "idempotent": False}
    assert repeated == {"ok": True, "idempotent": True}

    conflict = JobResultRequest(
        status="success",
        claim_token=claim_token,
        result={"updates": 99},
    )
    with pytest.raises(HTTPException) as exc:
        main.job_result(agent.id, job.id, conflict, x_agent_token=agent_token, db=db)
    assert exc.value.status_code == 409


def test_expired_claim_is_requeued_before_execution(db):
    token = "claim-" + ("c" * 32)
    _, _, job, _ = seed_job(
        db,
        status="claimed",
        lease_expires_at=main.now() - timedelta(seconds=5),
        claim_token=token,
    )

    result = main.sweep_expired_job_leases(db)
    db.refresh(job)

    assert result == {"requeued": 1, "stalled": 0}
    assert job.status == "pending"
    assert job.claim_token_hash == ""
    assert job.lease_expires_at is None


def test_expired_running_job_stalls_and_is_not_requeued(db):
    token = "claim-" + ("r" * 32)
    _, _, job, _ = seed_job(
        db,
        status="running",
        lease_expires_at=main.now() - timedelta(seconds=5),
        claim_token=token,
    )

    result = main.sweep_expired_job_leases(db)
    db.refresh(job)

    assert result == {"requeued": 0, "stalled": 1}
    assert job.status == "stalled"
    assert job.claim_token_hash == hash_token(token)


def test_stalled_attempt_may_report_terminal_result_until_manual_retry(db):
    claim_token = "claim-" + ("s" * 32)
    agent, _, job, agent_token = seed_job(
        db,
        status="running",
        lease_expires_at=main.now() - timedelta(seconds=5),
        claim_token=claim_token,
    )
    main.sweep_expired_job_leases(db)

    result = main.job_result(
        agent.id,
        job.id,
        JobResultRequest(
            status="success",
            claim_token=claim_token,
            result={"late": True},
        ),
        x_agent_token=agent_token,
        db=db,
    )

    assert result["ok"] is True
    db.refresh(job)
    assert job.status == "success"


def test_manual_retry_invalidates_old_claim(db):
    claim_token = "claim-" + ("t" * 32)
    agent, _, job, agent_token = seed_job(
        db,
        status="running",
        lease_expires_at=main.now() - timedelta(seconds=5),
        claim_token=claim_token,
    )
    main.sweep_expired_job_leases(db)

    retry = main.retry_stalled_job(
        job.id,
        JobRetryRequest(reason="Revisado pelo administrador", acknowledge_risk=True),
        principal={"actor": "user:test-admin", "role": "admin", "user_id": "test-admin"},
        db=db,
    )
    assert retry["ok"] is True

    db.refresh(job)
    assert job.status == "pending"
    assert job.claim_token_hash == ""

    with pytest.raises(HTTPException) as exc:
        main.job_result(
            agent.id,
            job.id,
            JobResultRequest(status="success", claim_token=claim_token),
            x_agent_token=agent_token,
            db=db,
        )
    assert exc.value.status_code == 409
