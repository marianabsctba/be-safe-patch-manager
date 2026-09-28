import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


TEST_DB = Path(__file__).resolve().parent / "test-risk-treatment.db"
TEST_DB.unlink(missing_ok=True)
SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "T" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"
os.environ["THREAT_INTEL_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app import main
from app.models import Agent, AssetRiskTreatment, AuditEvent
from app.schemas import AssetRiskTreatmentCreate, AssetRiskTreatmentUpdate


REFERENCE = datetime(2026, 9, 28, 11, 0, tzinfo=timezone.utc)


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


def make_agent(aid="treatment-agent", tags=None):
    return Agent(
        id=aid,
        hostname=f"{aid}.local",
        os_family="linux",
        os_name="Linux",
        token_hash=(aid.replace("-", "") + "x" * 64)[:64],
        tags=main.dump(tags or []),
    )


def test_treatment_serialization_marks_overdue(db):
    agent = make_agent()
    treatment = AssetRiskTreatment(
        id="t1",
        agent=agent,
        owner="SOC",
        action="Aplicar correção validada",
        due_at=REFERENCE - timedelta(hours=1),
        status="in_progress",
        created_by="user:admin",
        updated_by="user:admin",
    )
    db.add_all([agent, treatment])
    db.commit()

    data = main.serialize_asset_risk_treatment(treatment, REFERENCE)

    assert data["active"] is True
    assert data["overdue"] is True


def test_create_treatment_blocks_duplicate_active_plan(db, monkeypatch):
    agent = make_agent()
    existing = AssetRiskTreatment(
        id="active",
        agent=agent,
        owner="Infra",
        action="Atualizar componente vulnerável",
        due_at=REFERENCE + timedelta(days=10),
        status="planned",
        created_by="user:admin",
        updated_by="user:admin",
    )
    db.add_all([agent, existing])
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)
    monkeypatch.setattr(main, "ASSET_RISK_APPETITE", 0)

    with pytest.raises(main.HTTPException) as exc:
        main.create_asset_risk_treatment(
            agent.id,
            AssetRiskTreatmentCreate(
                owner="SOC",
                action="Segundo plano concorrente",
                due_at=REFERENCE + timedelta(days=20),
            ),
            principal={"actor": "user:admin", "role": "admin"},
            db=db,
        )

    assert exc.value.status_code == 409


def test_completed_treatment_requires_evidence(db, monkeypatch):
    agent = make_agent()
    treatment = AssetRiskTreatment(
        id="complete-me",
        agent=agent,
        owner="Infra",
        action="Remover exposição externa",
        due_at=REFERENCE + timedelta(days=5),
        status="in_progress",
        created_by="user:admin",
        updated_by="user:admin",
    )
    db.add_all([agent, treatment])
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)

    with pytest.raises(main.HTTPException) as exc:
        main.update_asset_risk_treatment(
            agent.id,
            treatment.id,
            AssetRiskTreatmentUpdate(status="completed"),
            principal={"actor": "user:admin", "role": "admin"},
            db=db,
        )

    assert exc.value.status_code == 400


def test_create_and_complete_treatment_are_audited(db, monkeypatch):
    agent = make_agent()
    db.add(agent)
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)
    monkeypatch.setattr(main, "ASSET_RISK_APPETITE", 0)

    created = main.create_asset_risk_treatment(
        agent.id,
        AssetRiskTreatmentCreate(
            owner="Infra",
            action="Atualizar sistema e validar serviço",
            due_at=REFERENCE + timedelta(days=15),
        ),
        principal={"actor": "user:admin", "role": "admin"},
        db=db,
    )
    treatment_id = created["treatment"]["id"]

    updated = main.update_asset_risk_treatment(
        agent.id,
        treatment_id,
        AssetRiskTreatmentUpdate(
            status="completed",
            completion_evidence="Change CHG-2042 executada e rescan sem finding.",
        ),
        principal={"actor": "user:admin", "role": "admin"},
        db=db,
    )

    assert updated["treatment"]["status"] == "completed"
    assert updated["treatment"]["completed_at"] == REFERENCE.isoformat()

    events = db.query(AuditEvent).filter(
        AuditEvent.object_id == agent.id,
        AuditEvent.event_type.in_([
            "asset_risk.treatment.created",
            "asset_risk.treatment.updated",
        ]),
    ).order_by(AuditEvent.id.asc()).all()
    assert [event.event_type for event in events] == [
        "asset_risk.treatment.created",
        "asset_risk.treatment.updated",
    ]


def test_asset_report_distinguishes_in_treatment_and_overdue(db, monkeypatch):
    monkeypatch.setattr(main, "ASSET_RISK_APPETITE", 100)
    monkeypatch.setattr(
        main,
        "asset_risk_score",
        lambda agent, findings, reference=None: {
            "score": 800.0,
            "level": "high",
            "asset_criticality": {"score": 4, "source": "tags", "contributors": [], "tags": []},
            "exposure": {"external": False, "multiplier": 1.0, "contributors": [], "source": "default"},
            "compensating": {"multiplier": 1.0, "controls": [], "source": "tags"},
            "open_findings": 1,
            "buckets": {},
            "decomposition": [],
            "top_factors": [],
        },
    )

    active_agent = make_agent("active-treatment")
    overdue_agent = make_agent("overdue-treatment")
    active = AssetRiskTreatment(
        id="active-plan",
        agent=active_agent,
        owner="Infra",
        action="Aplicar patch",
        due_at=REFERENCE + timedelta(days=2),
        status="in_progress",
        created_by="user:admin",
        updated_by="user:admin",
    )
    overdue = AssetRiskTreatment(
        id="overdue-plan",
        agent=overdue_agent,
        owner="Infra",
        action="Atualizar appliance",
        due_at=REFERENCE - timedelta(days=1),
        status="planned",
        created_by="user:admin",
        updated_by="user:admin",
    )
    db.add_all([active_agent, overdue_agent, active, overdue])
    db.commit()

    report = main.asset_risk_report(db, REFERENCE)
    rows = {row["agent_id"]: row for row in report["assets"]}

    assert rows["active-treatment"]["risk"]["governance_status"] == "in_treatment"
    assert rows["overdue-treatment"]["risk"]["governance_status"] == "treatment_overdue"
    assert report["summary"]["in_treatment_above_appetite"] == 1
    assert report["summary"]["overdue_treatment_above_appetite"] == 1



def test_treatment_is_rejected_when_asset_is_within_appetite(db, monkeypatch):
    agent = make_agent()
    db.add(agent)
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)
    monkeypatch.setattr(main, "ASSET_RISK_APPETITE", 700)

    with pytest.raises(main.HTTPException) as exc:
        main.create_asset_risk_treatment(
            agent.id,
            AssetRiskTreatmentCreate(
                owner="Infra",
                action="Aplicar correção planejada",
                due_at=REFERENCE + timedelta(days=10),
            ),
            principal={"actor": "user:admin", "role": "admin"},
            db=db,
        )

    assert exc.value.status_code == 409


def test_treatment_rejects_whitespace_fields_after_strip(db, monkeypatch):
    agent = make_agent()
    db.add(agent)
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)
    monkeypatch.setattr(main, "ASSET_RISK_APPETITE", 0)

    with pytest.raises(main.HTTPException) as exc:
        main.create_asset_risk_treatment(
            agent.id,
            AssetRiskTreatmentCreate(
                owner="  ",
                action="     ",
                due_at=REFERENCE + timedelta(days=10),
            ),
            principal={"actor": "user:admin", "role": "admin"},
            db=db,
        )

    assert exc.value.status_code == 400
