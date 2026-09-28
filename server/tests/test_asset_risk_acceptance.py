import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


TEST_DB = Path(__file__).resolve().parent / "test-risk-acceptance.db"
TEST_DB.unlink(missing_ok=True)
SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "K" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"
os.environ["THREAT_INTEL_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app import main
from app.models import Agent, AssetRiskAcceptance, AssetRiskPolicy, AuditEvent
from app.schemas import AssetRiskAcceptanceCreate, AssetRiskAcceptanceRevoke


REFERENCE = datetime(2026, 9, 27, 21, 0, tzinfo=timezone.utc)


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


def make_agent(aid="accept-agent", tags=None):
    return Agent(
        id=aid,
        hostname=f"{aid}.local",
        os_family="linux",
        os_name="Linux",
        token_hash=(aid.replace("-", "") + "x" * 64)[:64],
        tags=main.dump(tags or []),
    )


def test_active_acceptance_is_selected_and_serialized(db):
    agent = make_agent()
    active = AssetRiskAcceptance(
        id="a1",
        agent=agent,
        reason="Risco aceito durante migração",
        approved_by="user:admin",
        expires_at=REFERENCE + timedelta(days=10),
        created_at=REFERENCE,
    )
    expired = AssetRiskAcceptance(
        id="a2",
        agent=agent,
        reason="Antiga",
        approved_by="user:admin",
        expires_at=REFERENCE - timedelta(days=1),
        created_at=REFERENCE - timedelta(days=20),
    )
    db.add_all([agent, active, expired])
    db.commit()

    selected = main.active_asset_risk_acceptance(agent, REFERENCE)
    serialized = main.serialize_asset_risk_acceptance(active, REFERENCE)

    assert selected.id == "a1"
    assert serialized["active"] is True
    assert serialized["expired"] is False


def test_create_acceptance_requires_future_within_one_year(db, monkeypatch):
    agent = make_agent()
    db.add(agent)
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)

    with pytest.raises(main.HTTPException) as exc:
        main.create_asset_risk_acceptance(
            agent.id,
            AssetRiskAcceptanceCreate(
                reason="Validade longa demais",
                expires_at=REFERENCE + timedelta(days=366),
            ),
            principal={"actor": "user:admin", "role": "admin"},
            db=db,
        )
    assert exc.value.status_code == 400


def test_acceptance_create_and_revoke_are_audited(db, monkeypatch):
    agent = make_agent()
    db.add(agent)
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)
    monkeypatch.setattr(main, "ASSET_RISK_APPETITE", 0)

    created = main.create_asset_risk_acceptance(
        agent.id,
        AssetRiskAcceptanceCreate(
            reason="Exceção temporária durante substituição do sistema",
            expires_at=REFERENCE + timedelta(days=30),
        ),
        principal={"actor": "user:admin", "role": "admin"},
        db=db,
    )
    acceptance_id = created["acceptance"]["id"]

    revoked = main.revoke_asset_risk_acceptance(
        agent.id,
        acceptance_id,
        AssetRiskAcceptanceRevoke(reason="Mudança concluída antes do prazo"),
        principal={"actor": "user:admin", "role": "admin"},
        db=db,
    )

    assert revoked["acceptance"]["active"] is False
    events = db.query(AuditEvent).filter(
        AuditEvent.object_id == agent.id,
        AuditEvent.event_type.in_([
            "asset_risk.acceptance.created",
            "asset_risk.acceptance.revoked",
        ]),
    ).order_by(AuditEvent.id.asc()).all()
    assert [event.event_type for event in events] == [
        "asset_risk.acceptance.created",
        "asset_risk.acceptance.revoked",
    ]


def test_duplicate_active_acceptance_is_blocked(db, monkeypatch):
    agent = make_agent()
    acceptance = AssetRiskAcceptance(
        id="active-one",
        agent=agent,
        reason="Já aceito",
        approved_by="user:admin",
        expires_at=REFERENCE + timedelta(days=5),
        created_at=REFERENCE,
    )
    db.add_all([agent, acceptance])
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)
    monkeypatch.setattr(main, "ASSET_RISK_APPETITE", 0)

    with pytest.raises(main.HTTPException) as exc:
        main.create_asset_risk_acceptance(
            agent.id,
            AssetRiskAcceptanceCreate(
                reason="Segunda aceitação",
                expires_at=REFERENCE + timedelta(days=10),
            ),
            principal={"actor": "user:admin", "role": "admin"},
            db=db,
        )
    assert exc.value.status_code == 409


def test_asset_report_marks_above_appetite_as_accepted(db, monkeypatch):
    monkeypatch.setattr(main, "ASSET_RISK_APPETITE", 100)
    monkeypatch.setattr(
        main,
        "asset_risk_score",
        lambda agent, findings, reference=None: {
            "score": 900.0,
            "level": "critical",
            "asset_criticality": {"score": 5, "source": "tags", "contributors": [], "tags": ["tier0"]},
            "exposure": {"external": True, "multiplier": 1.2, "contributors": ["internet-facing"], "source": "tags"},
            "compensating": {"multiplier": 1.0, "controls": [], "source": "tags"},
            "open_findings": 1,
            "buckets": {},
            "decomposition": [],
            "top_factors": ["ativo crítico"],
        },
    )
    agent = make_agent(tags=["tier0", "internet-facing"])
    acceptance = AssetRiskAcceptance(
        id="accepted",
        agent=agent,
        reason="Risco aceito",
        approved_by="user:admin",
        expires_at=REFERENCE + timedelta(days=10),
        created_at=REFERENCE,
    )
    db.add_all([agent, acceptance])
    db.commit()

    report = main.asset_risk_report(db, REFERENCE)
    row = report["assets"][0]

    assert row["risk"]["above_risk_appetite"] is True
    assert row["risk"]["governance_status"] == "accepted"
    assert row["risk_acceptance"]["active"] is True
    assert report["summary"]["accepted_above_appetite"] == 1
    assert report["summary"]["unaccepted_above_appetite"] == 0



def test_acceptance_is_rejected_when_asset_is_within_appetite(db, monkeypatch):
    agent = make_agent()
    db.add(agent)
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)
    monkeypatch.setattr(main, "ASSET_RISK_APPETITE", 700)

    with pytest.raises(main.HTTPException) as exc:
        main.create_asset_risk_acceptance(
            agent.id,
            AssetRiskAcceptanceCreate(
                reason="Aceite sem risco acima do limite",
                expires_at=REFERENCE + timedelta(days=10),
            ),
            principal={"actor": "user:admin", "role": "admin"},
            db=db,
        )

    assert exc.value.status_code == 409
    assert exc.value.detail["message"] == "asset is not above its effective risk appetite"


def test_acceptance_rejects_whitespace_reason_after_strip(db, monkeypatch):
    agent = make_agent()
    db.add(agent)
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)
    monkeypatch.setattr(main, "ASSET_RISK_APPETITE", 0)

    with pytest.raises(main.HTTPException) as exc:
        main.create_asset_risk_acceptance(
            agent.id,
            AssetRiskAcceptanceCreate(
                reason="     ",
                expires_at=REFERENCE + timedelta(days=10),
            ),
            principal={"actor": "user:admin", "role": "admin"},
            db=db,
        )

    assert exc.value.status_code == 400
