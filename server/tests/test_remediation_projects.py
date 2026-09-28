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
