import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


TEST_DB = Path(__file__).resolve().parent / "test-remediation-projects.db"
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
from app.models import Agent, AuditEvent, RemediationProject, VulnerabilityFinding
from app.schemas import RemediationProjectCreate, RemediationProjectUpdate


REFERENCE = datetime(2026, 9, 28, 16, 0, tzinfo=timezone.utc)


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


def make_agent(aid, tags=None):
    return Agent(
        id=aid,
        hostname=f"{aid}.local",
        os_family="windows",
        os_name="Windows",
        token_hash=(aid.replace("-", "") + "x" * 64)[:64],
        tags=main.dump(tags or []),
    )


def make_finding(fid, agent, patch_ref="KB5039999", status="open"):
    seen = REFERENCE - timedelta(days=7)
    return VulnerabilityFinding(
        id=fid,
        source="openvas",
        external_id=f"ext-{fid}",
        scan_id="scan",
        agent=agent,
        host=agent.hostname,
        cve=f"CVE-2026-{10000 + len(fid)}",
        title=f"Finding {fid}",
        severity="critical",
        cvss=9.8,
        patch_refs_json=main.dump([patch_ref]),
        raw_json=main.dump({"threat_intel": {"epss": 0.9, "kev": True}}),
        status=status,
        first_seen=seen,
        last_seen=seen,
    )


def create_project(db, monkeypatch, *, name, scope_mode="static"):
    monkeypatch.setattr(main, "now", lambda: REFERENCE)
    return main.create_remediation_project(
        RemediationProjectCreate(
            name=name,
            patch_ref="KB5039999",
            scope_mode=scope_mode,
            scope_tag="prod",
            owner="Windows Team",
            due_at=REFERENCE + timedelta(days=30),
            reason="Reduzir risco associado ao patch prioritário",
        ),
        principal={"actor": "user:operator", "role": "operator"},
        db=db,
    )


def test_static_project_freezes_initial_scope(db, monkeypatch):
    agent = make_agent("static-agent", ["prod"])
    f1 = make_finding("static-f1", agent)
    f2 = make_finding("static-f2", agent)
    db.add_all([agent, f1, f2])
    db.commit()

    result = create_project(db, monkeypatch, name="Static project", scope_mode="static")
    project_id = result["project"]["id"]

    f3 = make_finding("static-f3", agent)
    db.add(f3)
    db.commit()

    project = db.get(RemediationProject, project_id)
    data = main.serialize_remediation_project(db, project, REFERENCE)

    assert data["baseline_findings"] == 2
    assert data["current_open_findings"] == 2
    assert data["new_findings_since_baseline"] == 0


def test_dynamic_project_absorbs_new_findings(db, monkeypatch):
    agent = make_agent("dynamic-agent", ["prod"])
    f1 = make_finding("dynamic-f1", agent)
    f2 = make_finding("dynamic-f2", agent)
    db.add_all([agent, f1, f2])
    db.commit()

    result = create_project(db, monkeypatch, name="Dynamic project", scope_mode="dynamic")
    project_id = result["project"]["id"]

    db.add(make_finding("dynamic-f3", agent))
    db.commit()

    project = db.get(RemediationProject, project_id)
    data = main.serialize_remediation_project(db, project, REFERENCE)

    assert data["baseline_findings"] == 2
    assert data["current_open_findings"] == 3
    assert data["new_findings_since_baseline"] == 1
    assert data["progress_percent"] == 0.0


def test_project_progress_tracks_closed_baseline_findings(db, monkeypatch):
    agent = make_agent("progress-agent", ["prod"])
    f1 = make_finding("progress-f1", agent)
    f2 = make_finding("progress-f2", agent)
    db.add_all([agent, f1, f2])
    db.commit()

    result = create_project(db, monkeypatch, name="Progress project")
    project_id = result["project"]["id"]

    f1.status = "remediated"
    f1.resolved_at = REFERENCE
    db.commit()

    project = db.get(RemediationProject, project_id)
    data = main.serialize_remediation_project(db, project, REFERENCE)

    assert data["current_open_findings"] == 1
    assert data["closed_from_baseline"] == 1
    assert data["progress_percent"] == 50.0


def test_project_cannot_complete_with_open_findings(db, monkeypatch):
    agent = make_agent("complete-agent", ["prod"])
    finding = make_finding("complete-f", agent)
    db.add_all([agent, finding])
    db.commit()

    result = create_project(db, monkeypatch, name="Completion guard")
    project_id = result["project"]["id"]

    with pytest.raises(main.HTTPException) as exc:
        main.update_remediation_project(
            project_id,
            RemediationProjectUpdate(
                status="completed",
                reason="Tentativa de concluir antes da verificação",
            ),
            principal={"actor": "user:operator", "role": "operator"},
            db=db,
        )

    assert exc.value.status_code == 409


def test_project_can_complete_after_scope_is_closed(db, monkeypatch):
    agent = make_agent("done-agent", ["prod"])
    finding = make_finding("done-f", agent)
    db.add_all([agent, finding])
    db.commit()

    result = create_project(db, monkeypatch, name="Completed project")
    project_id = result["project"]["id"]

    finding.status = "remediated"
    finding.resolved_at = REFERENCE
    db.commit()

    updated = main.update_remediation_project(
        project_id,
        RemediationProjectUpdate(
            status="completed",
            reason="Todos os findings do escopo foram encerrados",
        ),
        principal={"actor": "user:operator", "role": "operator"},
        db=db,
    )

    assert updated["project"]["status"] == "completed"
    assert updated["project"]["current_open_findings"] == 0
    assert updated["project"]["progress_percent"] == 100.0


def test_project_creation_is_audited(db, monkeypatch):
    agent = make_agent("audit-agent", ["prod"])
    db.add_all([agent, make_finding("audit-f", agent)])
    db.commit()

    result = create_project(db, monkeypatch, name="Audit project")

    event = db.query(AuditEvent).filter(
        AuditEvent.event_type == "remediation_project.created"
    ).one()
    assert event.object_id == result["project"]["id"]



def test_dynamic_project_separates_scope_departure_from_remediation(db, monkeypatch):
    agent = make_agent("scope-drift-agent", ["prod"])
    finding = make_finding("scope-drift-f", agent)
    db.add_all([agent, finding])
    db.commit()

    result = create_project(db, monkeypatch, name="Scope drift project", scope_mode="dynamic")
    project_id = result["project"]["id"]

    agent.tags = main.dump(["lab"])
    db.commit()

    project = db.get(RemediationProject, project_id)
    data = main.serialize_remediation_project(db, project, REFERENCE)

    assert data["current_open_findings"] == 0
    assert data["baseline_open_findings"] == 1
    assert data["closed_from_baseline"] == 0
    assert data["scope_departures"] == 1
    assert data["tracked_open_findings"] == 1
    assert data["progress_percent"] == 0.0
    assert data["achieved"] is False



def test_project_snapshot_history_tracks_burndown(db, monkeypatch):
    agent = make_agent("history-agent", ["prod"])
    f1 = make_finding("history-f1", agent)
    f2 = make_finding("history-f2", agent)
    db.add_all([agent, f1, f2])
    db.commit()

    result = create_project(db, monkeypatch, name="History project")
    project_id = result["project"]["id"]

    initial = main.remediation_project_history(db, project_id)
    assert len(initial["items"]) == 1
    assert initial["items"][0]["tracked_open_findings"] == 2
    assert initial["items"][0]["progress_percent"] == 0.0

    f1.status = "remediated"
    f1.resolved_at = REFERENCE
    db.commit()

    main.capture_remediation_project_snapshots(
        db,
        source="test-burndown",
        reference=REFERENCE + timedelta(hours=1),
        minimum_interval_seconds=0,
        project_ids={project_id},
    )
    history = main.remediation_project_history(db, project_id)
    assert len(history["items"]) == 2
    assert history["items"][0]["tracked_open_findings"] == 1
    assert history["items"][0]["progress_percent"] == 50.0
    assert history["items"][0]["source"] == "test-burndown"


def test_project_snapshot_interval_prevents_noise(db, monkeypatch):
    agent = make_agent("history-interval-agent", ["prod"])
    db.add_all([agent, make_finding("history-interval-f", agent)])
    db.commit()

    result = create_project(db, monkeypatch, name="Interval project")
    project_id = result["project"]["id"]

    capture = main.capture_remediation_project_snapshots(
        db,
        source="too-soon",
        reference=REFERENCE + timedelta(minutes=10),
        minimum_interval_seconds=3600,
        project_ids={project_id},
    )

    assert capture["created"] == 0
    assert capture["skipped"] == 1



def test_project_intelligence_exposes_risk_and_schedule_signals(db, monkeypatch):
    agent = make_agent("intel-agent", ["prod", "internet-facing"])
    f1 = make_finding("intel-f1", agent)
    f2 = make_finding("intel-f2", agent)
    db.add_all([agent, f1, f2])
    db.commit()

    result = create_project(db, monkeypatch, name="Intelligence project")
    project = db.get(RemediationProject, result["project"]["id"])
    project.created_at = REFERENCE - timedelta(days=10)
    project.due_at = REFERENCE + timedelta(days=10)
    db.commit()

    data = main.serialize_remediation_project(db, project, REFERENCE)

    assert data["kev_findings"] == 2
    assert data["sla_breached"] == 2
    assert data["external_assets"] == 1
    assert data["average_age_days"] >= 7
    assert data["oldest_age_days"] >= 7
    assert data["max_epss"] == 0.9
    assert data["expected_progress_percent"] == 50.0
    assert data["schedule_variance_percent"] == -50.0
    assert data["attention_status"] == "critical"
    assert data["remaining_risk_reduction"] >= 0
    assert data["realized_risk_reduction"] == 0.0


def test_project_intelligence_tracks_realized_risk_reduction(db, monkeypatch):
    agent = make_agent("risk-progress-agent", ["prod", "internet-facing"])
    f1 = make_finding("risk-progress-f1", agent)
    f2 = make_finding("risk-progress-f2", agent)
    db.add_all([agent, f1, f2])
    db.commit()

    result = create_project(db, monkeypatch, name="Risk progress project")
    project = db.get(RemediationProject, result["project"]["id"])
    baseline = result["project"]["baseline_risk_reduction"]

    f1.status = "remediated"
    f1.resolved_at = REFERENCE
    db.commit()

    data = main.serialize_remediation_project(db, project, REFERENCE)

    assert data["baseline_risk_reduction"] == baseline
    assert data["remaining_risk_reduction"] <= baseline
    assert data["realized_risk_reduction"] >= 0
    assert 0.0 <= data["risk_reduction_progress_percent"] <= 100.0


def test_project_history_persists_intelligence_fields(db, monkeypatch):
    agent = make_agent("intel-history-agent", ["prod", "internet-facing"])
    finding = make_finding("intel-history-f", agent)
    db.add_all([agent, finding])
    db.commit()

    result = create_project(db, monkeypatch, name="Intelligence history")
    project_id = result["project"]["id"]

    history = main.remediation_project_history(db, project_id)
    item = history["items"][0]

    assert "remaining_risk_reduction" in item
    assert "realized_risk_reduction" in item
    assert "risk_reduction_progress_percent" in item
    assert "expected_progress_percent" in item
    assert "schedule_variance_percent" in item
    assert item["kev_findings"] == 1
    assert item["sla_breached"] == 1
    assert item["external_assets"] == 1
    assert item["attention_status"] in {"critical", "needs_attention", "watch", "on_track"}
