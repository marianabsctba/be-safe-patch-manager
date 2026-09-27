import json
import os
import sys
import time
from pathlib import Path

from fastapi.testclient import TestClient


TEST_DB = Path(__file__).resolve().parent / "test-observability.db"
TEST_DB.unlink(missing_ok=True)

SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "O" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app.main import app, now
from app.models import AdminUser, Agent, Campaign, IntegrationState, PatchJob, VulnerabilityFinding
from app import observability


def setup_function():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def teardown_function():
    Base.metadata.drop_all(bind=engine)


def add_admin(db):
    user = AdminUser(
        id="obs-admin",
        username="obs.admin",
        password_hash="not-used-by-this-test",
        role="admin",
        active=True,
    )
    db.add(user)
    db.commit()
    return user


def test_ready_requires_database_and_active_admin():
    client = TestClient(app)

    no_admin = client.get("/ready")
    assert no_admin.status_code == 503
    assert no_admin.json()["database"] == "ok"
    assert no_admin.json()["active_admin"] is False

    db = SessionLocal()
    try:
        add_admin(db)
    finally:
        db.close()

    ready = client.get("/ready")
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"
    assert ready.json()["database"] == "ok"
    assert ready.json()["active_admin"] is True


def test_metrics_are_aggregated_and_do_not_expose_endpoint_identity(tmp_path, monkeypatch):
    status_file = tmp_path / "backup-status.json"
    status_file.write_text(
        json.dumps({
            "status": "ok",
            "epoch": int(time.time()) - 3600,
            "time": "2026-09-27T12:00:00Z",
            "file": "patchmgr-test.dump",
            "size_bytes": 123456,
            "sha256": "deadbeef",
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(observability, "BACKUP_STATUS_FILE", status_file)

    db = SessionLocal()
    try:
        add_admin(db)
        agent = Agent(
            id="obs-agent",
            hostname="sensitive-hostname-should-not-leak",
            os_family="linux",
            os_name="Linux",
            os_version="test",
            arch="x86_64",
            ip_address="10.123.45.67",
            tags='["pilot"]',
            token_hash="1" * 64,
            client_cert_fingerprint="a" * 40,
            last_seen=now(),
            pending_updates=4,
            critical_updates=2,
            reboot_required=True,
        )
        campaign = Campaign(
            id="obs-campaign",
            name="Observability test",
            target_os="linux",
            ring_percent=10,
            action="install_updates",
            status="deployed",
        )
        job = PatchJob(
            id="obs-job",
            campaign=campaign,
            agent=agent,
            action="install_updates",
            status="stalled",
        )
        finding = VulnerabilityFinding(
            id="obs-vuln",
            source="openvas",
            external_id="obs-result",
            scan_id="scan",
            agent=agent,
            host=agent.hostname,
            ip_address=agent.ip_address,
            cve="CVE-2026-99999",
            title="Sensitive finding title",
            severity="high",
            cvss=8.8,
            status="open",
        )
        greenbone = IntegrationState(
            name="greenbone",
            enabled=True,
            status="ok",
            last_success_at=now(),
        )
        db.add_all([agent, campaign, job, finding, greenbone])
        db.commit()
    finally:
        db.close()

    client = TestClient(app)
    response = client.get("/metrics")
    assert response.status_code == 200
    body = response.text

    assert "patch_manager_database_up 1.0" in body
    assert "patch_manager_agents_online 1.0" in body
    assert 'patch_manager_agents{os_family="linux"} 1.0' in body
    assert 'patch_manager_jobs{status="stalled"} 1.0' in body
    assert 'patch_manager_campaigns{status="deployed"} 1.0' in body
    assert 'patch_manager_vulnerabilities{status="open",severity="high"} 1.0' in body
    assert "patch_manager_backup_status 1.0" in body
    assert "patch_manager_backup_size_bytes 123456.0" in body
    assert "patch_manager_greenbone_sync_ok 1.0" in body

    assert "sensitive-hostname-should-not-leak" not in body
    assert "10.123.45.67" not in body
    assert "CVE-2026-99999" not in body
    assert ("a" * 40) not in body


def test_backup_state_reports_age_without_exposing_filename(tmp_path, monkeypatch):
    status_file = tmp_path / "backup-status.json"
    epoch = int(time.time()) - 7200
    status_file.write_text(
        json.dumps({
            "status": "ok",
            "epoch": epoch,
            "file": "private-backup-name.dump",
            "size_bytes": 42,
            "sha256": "secret-checksum",
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(observability, "BACKUP_STATUS_FILE", status_file)

    state = observability._backup_state()
    assert state["ok"] == 1.0
    assert state["timestamp"] == float(epoch)
    assert 7100 <= state["age"] <= 7300
    assert state["size"] == 42.0


def test_http_metric_uses_route_template_not_agent_identifier():
    client = TestClient(app)
    agent_id = "identity-that-must-not-become-a-label"
    response = client.put(f"/api/admin/agents/{agent_id}/tags", json={"tags": ["x"]})
    assert response.status_code == 401

    metrics = client.get("/metrics").text
    assert 'route="/api/admin/agents/{agent_id}/tags"' in metrics
    assert agent_id not in metrics
