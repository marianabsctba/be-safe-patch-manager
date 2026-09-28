import json
import os
import sys
import time
from datetime import timedelta
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
from app.models import AdminUser, Agent, Campaign, IntegrationState, PatchJob, RemediationEvidence, RemediationProject, RemediationProjectSnapshot, RiskReductionGoal, VulnerabilityFinding
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
            inventory_json=json.dumps({
                "agent": {
                    "version": "0.13.0",
                    "protocol": 2,
                    "capabilities": [
                        "scan_updates",
                        "install_updates",
                        "job_leases_v1",
                        "health_telemetry_v1",
                    ],
                },
                "update": {
                    "status": "staged",
                    "current_version": "0.15.0",
                    "staged_version": "0.16.0"
                },
                "activation": {
                    "status": "rolled_back",
                    "previous_version": "0.15.0",
                    "target_version": "0.16.0",
                    "attempts": 4
                },
                "health": {
                    "collected_at": now().isoformat(),
                    "cpu_percent": 25.0,
                    "memory_percent": 50.0,
                    "disk": {"free_percent": 40.0},
                    "services": {"nginx": {"healthy": False, "status": "failed"}},
                    "applications": {"api": {"healthy": True, "status_code": 200}},
                    "errors": [],
                }
            }),
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
        expired_approval = PatchJob(
            id="obs-expired-approval",
            campaign=campaign,
            agent=agent,
            action="activate_agent_update",
            status="pending",
            payload_json=json.dumps({
                "expected_version": "0.17.0",
                "approval_expires_at": (now() - timedelta(minutes=1)).isoformat(),
            }),
        )
        invalidated_approval = PatchJob(
            id="obs-invalidated-approval",
            campaign=campaign,
            agent=agent,
            action="activate_agent_update",
            status="skipped",
            error="agent update authorization invalidated: approval_expired",
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
        evidence = RemediationEvidence(
            id="obs-evidence",
            finding_id=finding.id,
            campaign_id=campaign.id,
            job_id=job.id,
            agent_id=agent.id,
            source="openvas",
            cve=finding.cve,
            greenbone_task_id="task-observability",
            baseline_report_id="baseline",
            rescan_report_id="rescan",
            status="verified",
            evidence_json="{}",
            verified_at=now(),
        )
        db.add_all([
            agent,
            campaign,
            job,
            expired_approval,
            invalidated_approval,
            finding,
            greenbone,
            evidence,
        ])
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
    vuln_line = next(
        line for line in body.splitlines()
        if line.startswith("patch_manager_vulnerabilities{")
    )
    assert 'status="open"' in vuln_line
    assert 'severity="high"' in vuln_line
    assert vuln_line.endswith(" 1.0")
    assert "patch_manager_backup_status 1.0" in body
    assert "patch_manager_backup_size_bytes 123456.0" in body
    assert "patch_manager_greenbone_sync_ok 1.0" in body
    assert "patch_manager_health_telemetry_agents 1.0" in body
    assert "patch_manager_health_services_unhealthy 1.0" in body
    assert "patch_manager_health_applications_unhealthy 0.0" in body
    assert "patch_manager_health_collection_errors 0.0" in body
    assert 'patch_manager_remediation_evidence{status="verified"} 1.0' in body
    assert 'patch_manager_agent_compatibility{status="supported"} 1.0' in body
    assert "patch_manager_agent_compatibility_enforced" in body
    assert 'patch_manager_agent_update_state{status="staged"} 1.0' in body
    assert "patch_manager_agent_update_distribution_enabled" in body
    assert 'patch_manager_agent_activation_state{status="rolled_back"} 1.0' in body
    assert "patch_manager_agent_update_approvals_pending 1.0" in body
    assert "patch_manager_agent_update_approvals_expired 1.0" in body
    assert "patch_manager_agent_update_authorizations_invalidated 1.0" in body

    assert "sensitive-hostname-should-not-leak" not in body
    assert "10.123.45.67" not in body
    assert "CVE-2026-99999" not in body
    assert ("a" * 40) not in body
    assert "health_telemetry_v1" not in body


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



def test_threat_intel_metrics_distinguish_degraded_and_stale(monkeypatch):
    monkeypatch.setattr(observability, "THREAT_INTEL_STALE_SECONDS", 3600)

    db = SessionLocal()
    try:
        db.add(IntegrationState(
            name="threat_intel",
            enabled=True,
            status="degraded",
            last_success_at=now() - timedelta(hours=2),
            details_json='{"source_errors":{"epss":"timeout"}}',
        ))
        db.commit()
    finally:
        db.close()

    client = TestClient(app)
    body = client.get("/metrics").text

    assert "patch_manager_threat_intel_sync_healthy 1.0" in body
    assert "patch_manager_threat_intel_degraded 1.0" in body
    assert "patch_manager_threat_intel_stale 1.0" in body
    age_line = next(
        line for line in body.splitlines()
        if line.startswith("patch_manager_threat_intel_age_seconds ")
    )
    assert float(age_line.split()[-1]) >= 3600



def test_metrics_expose_overdue_risk_programs():
    db = SessionLocal()
    try:
        project = RemediationProject(
            id="obs-project-overdue",
            name="Obs Project Overdue",
            patch_ref="KB5099999",
            scope_mode="static",
            scope_tag="",
            owner="SecOps",
            due_at=now() - timedelta(hours=2),
            status="active",
            baseline_findings=1,
            baseline_assets=1,
            baseline_risk_reduction=10.0,
            scope_snapshot_json='{"finding_ids":[]}',
            reason="Teste de observabilidade",
            created_by="user:test",
            updated_by="user:test",
        )
        goal = RiskReductionGoal(
            id="obs-goal-overdue",
            name="Obs Goal Overdue",
            scope_tag="",
            goal_type="open_findings_max",
            target_value=0.0,
            baseline_value=1.0,
            owner="SecOps",
            due_at=now() - timedelta(hours=1),
            status="active",
            reason="Teste de observabilidade",
            created_by="user:test",
            updated_by="user:test",
        )
        snapshot = RemediationProjectSnapshot(
            project=project,
            tracked_open_findings=1,
            current_scope_findings=1,
            current_assets=1,
            closed_from_baseline=0,
            new_findings_since_baseline=0,
            scope_departures=0,
            progress_percent=25.0,
            remaining_risk_reduction=8.0,
            realized_risk_reduction=2.0,
            risk_reduction_progress_percent=20.0,
            expected_progress_percent=50.0,
            schedule_variance_percent=-25.0,
            sla_breached=1,
            kev_findings=1,
            external_assets=1,
            average_age_days=14.0,
            oldest_age_days=14.0,
            attention_status="critical",
            pace_status="overdue",
            source="test",
            captured_at=now(),
        )
        db.add_all([project, snapshot, goal])
        db.commit()
    finally:
        db.close()

    body = TestClient(app).get("/metrics").text

    assert 'patch_manager_remediation_projects{status="active"} 1.0' in body
    assert "patch_manager_remediation_projects_overdue 1.0" in body
    assert 'patch_manager_remediation_projects_attention{status="critical"} 1.0' in body
    assert "patch_manager_remediation_projects_remaining_risk_reduction 8.0" in body
    assert "patch_manager_remediation_projects_realized_risk_reduction 2.0" in body
    assert "patch_manager_remediation_projects_kev_findings 1.0" in body
    assert "patch_manager_remediation_projects_sla_breached 1.0" in body
    assert 'patch_manager_risk_goals{status="active"} 1.0' in body
    assert "patch_manager_risk_goals_overdue 1.0" in body
