import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


TEST_DB = Path(__file__).resolve().parent / "test-remediation-evidence.db"
TEST_DB.unlink(missing_ok=True)

SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "R" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app import main
from app.models import Agent, Campaign, PatchJob, RemediationEvidence, VulnerabilityFinding


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


def seed_source(db, external_id="task-one:stable-finding"):
    agent = Agent(
        id="rem-agent",
        hostname="rem-host",
        os_family="linux",
        os_name="Linux",
        token_hash="a" * 64,
        last_seen=main.now(),
        inventory_json="{}",
        patch_scan_json="[]",
    )
    finding = VulnerabilityFinding(
        id="rem-finding",
        source="openvas",
        external_id=external_id,
        scan_id="baseline-report",
        agent=agent,
        host="10.0.0.5",
        ip_address="10.0.0.5",
        cve="CVE-2026-12345",
        title="Test finding",
        severity="high",
        cvss=8.8,
        status="open",
        raw_json=json.dumps({
            "greenbone_task_id": "task-one",
            "greenbone_report_id": "baseline-report",
            "nvt_oid": "1.3.6.1.4.1.test",
        }),
    )
    campaign = Campaign(
        id="rem-campaign",
        name="Remediation",
        target_os="linux",
        ring_percent=100,
        action="install_updates",
        status="deployed",
        payload_json=json.dumps({
            "source_finding_id": finding.id,
            "source_cve": finding.cve,
            "post_patch_validation": True,
        }),
    )
    db.add_all([agent, finding, campaign])
    db.commit()
    return agent, finding, campaign


def test_remediation_evidence_is_created_with_install_job(db):
    agent, finding, campaign = seed_source(db)

    jobs = main.add_ring_jobs(db, campaign, [agent], 100)
    db.commit()

    assert len(jobs) == 1
    evidence = db.query(RemediationEvidence).one()
    assert evidence.finding_id == finding.id
    assert evidence.job_id == jobs[0].id
    assert evidence.campaign_id == campaign.id
    assert evidence.agent_id == agent.id
    assert evidence.greenbone_task_id == "task-one"
    assert evidence.baseline_report_id == "baseline-report"
    assert evidence.status == "waiting_validation"


def test_validated_job_requests_exact_greenbone_rescan(db, monkeypatch):
    agent, finding, campaign = seed_source(db)
    job = main.add_ring_jobs(db, campaign, [agent], 100)[0]
    job.status = "success"
    job.finished_at = main.now()
    db.commit()
    evidence = db.query(RemediationEvidence).one()

    monkeypatch.setattr(main, "job_post_patch_validation", lambda job: {
        "status": "passed",
        "reason": "healthy",
    })
    monkeypatch.setattr(main, "get_greenbone_config", lambda: SimpleNamespace(enabled=True))
    monkeypatch.setattr(main, "public_greenbone_config", lambda cfg: {
        "enabled": True,
        "configured": True,
    })
    monkeypatch.setattr(main, "start_greenbone_task_rescan", lambda task_id, cfg: {
        "task_id": task_id,
        "task_name": "Endpoint scan",
        "previous_status": "Done",
        "report_id": "post-patch-report",
    })

    requested = main.start_remediation_rescan(db, evidence, "system")
    db.refresh(evidence)

    assert requested is True
    assert evidence.status == "rescan_requested"
    assert evidence.rescan_report_id == "post-patch-report"
    assert evidence.requested_at is not None
    data = json.loads(evidence.evidence_json)
    assert data["rescan"]["report_id"] == "post-patch-report"
    assert data["validation"]["status"] == "passed"


def test_rescan_is_not_requested_before_health_validation_passes(db, monkeypatch):
    agent, finding, campaign = seed_source(db)
    job = main.add_ring_jobs(db, campaign, [agent], 100)[0]
    job.status = "success"
    db.commit()
    evidence = db.query(RemediationEvidence).one()

    monkeypatch.setattr(main, "job_post_patch_validation", lambda job: {
        "status": "waiting",
        "reason": "waiting for post-patch health telemetry",
    })

    called = {"value": False}
    def should_not_start(*args, **kwargs):
        called["value"] = True
        raise AssertionError("rescan must not start before validation")

    monkeypatch.setattr(main, "start_greenbone_task_rescan", should_not_start)

    assert main.start_remediation_rescan(db, evidence, "system") is False
    assert called["value"] is False
    db.refresh(evidence)
    assert evidence.status == "waiting_validation"


def seed_requested_evidence(db, external_id="task-one:stable-finding"):
    agent, finding, campaign = seed_source(db, external_id=external_id)
    job = main.add_ring_jobs(db, campaign, [agent], 100)[0]
    job.status = "success"
    job.finished_at = main.now()
    db.commit()
    evidence = db.query(RemediationEvidence).one()
    evidence.status = "rescan_requested"
    evidence.rescan_report_id = "post-patch-report"
    evidence.requested_at = main.now()
    db.commit()
    return finding, evidence


def test_exact_completed_rescan_absence_marks_remediated(db):
    finding, evidence = seed_requested_evidence(db)

    result = main.reconcile_remediation_evidence(db, [{
        "task_id": "task-one",
        "task_name": "Endpoint scan",
        "task_status": "Done",
        "report_id": "post-patch-report",
        "external_ids": [],
        "finding_count": 0,
    }])

    db.refresh(finding)
    db.refresh(evidence)
    assert result["verified"] == 1
    assert result["still_detected"] == 0
    assert evidence.status == "verified"
    assert evidence.verified_at is not None
    assert finding.status == "remediated"
    assert finding.resolved_at is not None

    proof = json.loads(evidence.evidence_json)["verification"]
    assert proof["report_id"] == "post-patch-report"
    assert proof["detected"] is False


def test_exact_completed_rescan_presence_keeps_finding_open(db):
    finding, evidence = seed_requested_evidence(db)

    result = main.reconcile_remediation_evidence(db, [{
        "task_id": "task-one",
        "task_name": "Endpoint scan",
        "task_status": "Done",
        "report_id": "post-patch-report",
        "external_ids": [finding.external_id],
        "finding_count": 1,
    }])

    db.refresh(finding)
    db.refresh(evidence)
    assert result["verified"] == 0
    assert result["still_detected"] == 1
    assert evidence.status == "still_detected"
    assert finding.status == "open"
    assert finding.resolved_at is None


def test_wrong_or_running_report_never_proves_remediation(db):
    finding, evidence = seed_requested_evidence(db)

    wrong = main.reconcile_remediation_evidence(db, [{
        "task_id": "task-one",
        "task_status": "Done",
        "report_id": "different-report",
        "external_ids": [],
        "finding_count": 0,
    }])
    db.refresh(evidence)
    assert wrong["waiting"] == 1
    assert evidence.status == "rescan_requested"

    running = main.reconcile_remediation_evidence(db, [{
        "task_id": "task-one",
        "task_status": "Running",
        "report_id": "post-patch-report",
        "external_ids": [],
        "finding_count": 0,
    }])
    db.refresh(evidence)
    assert running["waiting"] == 1
    assert evidence.status == "rescan_requested"
    db.refresh(finding)
    assert finding.status == "open"


def test_accepted_risk_status_is_not_overwritten_by_verified_evidence(db):
    finding, evidence = seed_requested_evidence(db)
    finding.status = "accepted_risk"
    db.commit()

    main.reconcile_remediation_evidence(db, [{
        "task_id": "task-one",
        "task_status": "Done",
        "report_id": "post-patch-report",
        "external_ids": [],
        "finding_count": 0,
    }])

    db.refresh(finding)
    db.refresh(evidence)
    assert evidence.status == "verified"
    assert finding.status == "accepted_risk"
