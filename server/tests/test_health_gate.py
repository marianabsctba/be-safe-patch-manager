import json
import os
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi import HTTPException


TEST_DB = Path(__file__).resolve().parent / "test-health-gate.db"
TEST_DB.unlink(missing_ok=True)

SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "H" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app import main
from app.models import Agent, Campaign, PatchJob
from app.schemas import CampaignCreate


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


def policy(**overrides):
    value = {
        "enabled": True,
        "required": True,
        "cpu_max_percent": 95.0,
        "cpu_max_delta": 40.0,
        "memory_max_percent": 95.0,
        "memory_max_delta": 20.0,
        "disk_min_free_percent": 5.0,
        "disk_max_free_drop": 10.0,
        "critical_services": ["nginx"],
        "application_checks": [{"name": "api", "url": "http://127.0.0.1:8081/health"}],
    }
    value.update(overrides)
    return value


def health(cpu=20.0, memory=50.0, disk_free=40.0, service=True, app=True, collected_at=None):
    return {
        "schema": 1,
        "collected_at": collected_at or main.now().isoformat(),
        "cpu_percent": cpu,
        "memory_percent": memory,
        "disk": {"path": "/", "free_percent": disk_free, "free_bytes": 1000},
        "services": {"nginx": {"healthy": service, "status": "active" if service else "failed"}},
        "applications": {
            "api": {
                "healthy": app,
                "status_code": 200 if app else 503,
                "latency_ms": 10.0,
            }
        },
        "errors": [],
    }


def test_health_regression_passes_within_policy():
    result = main.evaluate_health_regression(
        policy(),
        health(cpu=20, memory=45, disk_free=40),
        health(cpu=35, memory=55, disk_free=36),
    )

    assert result["status"] == "passed"
    assert result["issues"] == []
    assert result["comparisons"]["cpu"]["delta"] == 15
    assert result["comparisons"]["memory"]["delta"] == 10
    assert result["comparisons"]["disk_free"]["drop"] == 4


@pytest.mark.parametrize(
    ("current", "expected_fragment"),
    [
        (health(cpu=80), "CPU increased"),
        (health(memory=78), "memory increased"),
        (health(disk_free=20), "disk free dropped"),
        (health(service=False), "critical service nginx"),
        (health(app=False), "application health check api failed"),
    ],
)
def test_health_regression_blocks_real_regression(current, expected_fragment):
    result = main.evaluate_health_regression(policy(), health(), current)

    assert result["status"] == "failed"
    assert any(expected_fragment in issue for issue in result["issues"])


def test_required_health_gate_fails_closed_on_missing_baseline_metrics():
    baseline = health()
    baseline["cpu_percent"] = None

    result = main.evaluate_health_regression(policy(), baseline, health())

    assert result["status"] == "failed"
    assert "CPU telemetry unavailable" in result["issues"]


def test_required_health_gate_waits_for_post_patch_snapshot():
    result = main.evaluate_health_regression(policy(), health(), {})

    assert result["status"] == "waiting"
    assert result["reason"] == "waiting for post-patch health telemetry"


def test_application_checks_accept_only_loopback():
    allowed = CampaignCreate(
        name="allowed",
        health_gate_enabled=True,
        application_health_checks=[
            {"name": "local-api", "url": "http://127.0.0.1:8080/health"}
        ],
    )
    main.validate_campaign_policy(allowed)

    denied = CampaignCreate(
        name="denied",
        health_gate_enabled=True,
        application_health_checks=[
            {"name": "remote-api", "url": "https://example.com/health"}
        ],
    )
    with pytest.raises(HTTPException) as exc:
        main.validate_campaign_policy(denied)
    assert exc.value.status_code == 400
    assert "loopback" in str(exc.value.detail)


def test_job_validation_uses_fresh_post_patch_health(db):
    finished = main.now() - timedelta(minutes=2)
    baseline = health(cpu=20, memory=45, disk_free=50, collected_at=(finished - timedelta(minutes=1)).isoformat())
    current = health(cpu=25, memory=50, disk_free=48, collected_at=(finished + timedelta(minutes=1)).isoformat())

    agent = Agent(
        id="health-agent",
        hostname="health-host",
        os_family="linux",
        os_name="Linux",
        token_hash="a" * 64,
        last_seen=finished + timedelta(minutes=1),
        pending_updates=0,
        critical_updates=0,
        reboot_required=False,
        inventory_json=json.dumps({"health": current}),
        patch_scan_json="[]",
    )
    campaign = Campaign(
        id="health-campaign",
        name="Health campaign",
        target_os="linux",
        ring_percent=10,
        action="install_updates",
        status="deployed",
    )
    job = PatchJob(
        id="health-job",
        campaign=campaign,
        agent=agent,
        action="install_updates",
        status="success",
        finished_at=finished,
        payload_json=json.dumps({
            "post_patch_validation": True,
            "health_policy": policy(),
            "_baseline_pending_updates": 0,
            "_baseline_critical_updates": 0,
        }),
        result_json=json.dumps({"health_baseline": baseline}),
    )
    db.add_all([agent, campaign, job])
    db.commit()

    result = main.job_post_patch_validation(job)
    assert result["status"] == "passed"
    assert result["health_validation"]["status"] == "passed"

    current["services"]["nginx"] = {"healthy": False, "status": "failed"}
    agent.inventory_json = json.dumps({"health": current})
    db.commit()

    failed = main.job_post_patch_validation(job)
    assert failed["status"] == "failed"
    assert "critical service nginx is not healthy" in failed["health_validation"]["issues"]
