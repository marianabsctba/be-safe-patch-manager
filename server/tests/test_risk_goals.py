import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


TEST_DB = Path(__file__).resolve().parent / "test-risk-goals.db"
TEST_DB.unlink(missing_ok=True)
SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "G" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"
os.environ["THREAT_INTEL_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app import main
from app.models import Agent, AuditEvent, RiskReductionGoal, VulnerabilityFinding
from app.schemas import RiskReductionGoalCreate, RiskReductionGoalUpdate


REFERENCE = datetime(2026, 9, 28, 15, 0, tzinfo=timezone.utc)


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
        os_family="linux",
        os_name="Linux",
        token_hash=(aid.replace("-", "") + "x" * 64)[:64],
        tags=main.dump(tags or []),
    )


def make_finding(fid, agent, status="open"):
    seen = REFERENCE - timedelta(days=5)
    return VulnerabilityFinding(
        id=fid,
        source="openvas",
        external_id=f"ext-{fid}",
        scan_id="scan",
        agent=agent,
        host=agent.hostname,
        cve=f"CVE-2026-{10000 + len(fid)}",
        title=f"Finding {fid}",
        severity="high",
        cvss=8.0,
        status=status,
        first_seen=seen,
        last_seen=seen,
    )


def test_goal_freezes_baseline_and_tracks_live_progress(db, monkeypatch):
    agent = make_agent("goal-prod", ["prod"])
    f1 = make_finding("goal-f1", agent)
    f2 = make_finding("goal-f2", agent)
    db.add_all([agent, f1, f2])
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)

    created = main.create_risk_reduction_goal(
        RiskReductionGoalCreate(
            name="Reduzir findings Prod",
            scope_tag="prod",
            goal_type="open_findings_max",
            target_value=0,
            owner="SecOps",
            due_at=REFERENCE + timedelta(days=30),
            reason="Reduzir backlog de vulnerabilidades em produção",
        ),
        principal={"actor": "user:operator", "role": "operator"},
        db=db,
    )
    goal = created["goal"]

    assert goal["baseline_value"] == 2.0
    assert goal["current_value"] == 2.0
    assert goal["progress_percent"] == 0.0
    assert goal["scoped_assets"] == 1

    f1.status = "remediated"
    f1.resolved_at = REFERENCE
    db.commit()

    report = main.risk_reduction_goals_report(db, REFERENCE + timedelta(days=1))
    item = report["items"][0]

    assert item["baseline_value"] == 2.0
    assert item["current_value"] == 1.0
    assert item["progress_percent"] == 50.0


def test_goal_scope_by_tag_is_dynamic(db, monkeypatch):
    prod = make_agent("prod-a", ["prod"])
    lab = make_agent("lab-a", ["lab"])
    db.add_all([
        prod,
        lab,
        make_finding("prod-f", prod),
        make_finding("lab-f", lab),
    ])
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)

    result = main.create_risk_reduction_goal(
        RiskReductionGoalCreate(
            name="Prod only",
            scope_tag="prod",
            goal_type="open_findings_max",
            target_value=0,
            owner="VM Team",
            due_at=REFERENCE + timedelta(days=20),
            reason="Meta exclusiva para ativos de produção",
        ),
        principal={"actor": "user:operator", "role": "operator"},
        db=db,
    )

    assert result["goal"]["baseline_value"] == 1.0
    assert result["goal"]["scoped_assets"] == 1


def test_goal_cannot_complete_before_target(db, monkeypatch):
    agent = make_agent("goal-active", ["prod"])
    finding = make_finding("goal-active-f", agent)
    db.add_all([agent, finding])
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)

    created = main.create_risk_reduction_goal(
        RiskReductionGoalCreate(
            name="Finish only when done",
            scope_tag="prod",
            goal_type="open_findings_max",
            target_value=0,
            owner="SecOps",
            due_at=REFERENCE + timedelta(days=10),
            reason="Conclusão depende da redução real do backlog",
        ),
        principal={"actor": "user:operator", "role": "operator"},
        db=db,
    )

    with pytest.raises(main.HTTPException) as exc:
        main.update_risk_reduction_goal(
            created["goal"]["id"],
            RiskReductionGoalUpdate(
                status="completed",
                reason="Tentativa de concluir antes de atingir a meta",
            ),
            principal={"actor": "user:operator", "role": "operator"},
            db=db,
        )

    assert exc.value.status_code == 409


def test_goal_marks_overdue_when_deadline_passes(db):
    agent = make_agent("goal-overdue", ["prod"])
    db.add_all([agent, make_finding("goal-overdue-f", agent)])
    goal = RiskReductionGoal(
        id="goal-overdue-id",
        name="Overdue goal",
        scope_tag="prod",
        goal_type="open_findings_max",
        target_value=0,
        baseline_value=1,
        owner="SecOps",
        due_at=REFERENCE - timedelta(hours=1),
        status="active",
        reason="Meta vencida para validar o pace",
        created_by="user:operator",
        updated_by="user:operator",
        created_at=REFERENCE - timedelta(days=10),
        updated_at=REFERENCE - timedelta(days=10),
    )
    db.add(goal)
    db.commit()

    item = main.serialize_risk_reduction_goal(db, goal, REFERENCE)

    assert item["pace_status"] == "overdue"
    assert item["achieved"] is False


def test_goal_creation_is_audited(db, monkeypatch):
    agent = make_agent("goal-audit", ["prod"])
    db.add_all([agent, make_finding("goal-audit-f", agent)])
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)

    result = main.create_risk_reduction_goal(
        RiskReductionGoalCreate(
            name="Audit goal",
            scope_tag="prod",
            goal_type="open_findings_max",
            target_value=0,
            owner="SecOps",
            due_at=REFERENCE + timedelta(days=15),
            reason="Garantir trilha de auditoria da meta",
        ),
        principal={"actor": "user:operator", "role": "operator"},
        db=db,
    )

    event = db.query(AuditEvent).filter(
        AuditEvent.event_type == "risk_reduction.goal.created"
    ).one()
    assert event.object_id == result["goal"]["id"]
