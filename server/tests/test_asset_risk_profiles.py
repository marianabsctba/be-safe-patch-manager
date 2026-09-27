import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest


TEST_DB = Path(__file__).resolve().parent / "test-risk-profiles.db"
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
from app.models import Agent, AssetRiskProfile, AuditEvent
from app.schemas import AssetRiskProfileUpdate


REFERENCE = datetime(2026, 9, 27, 20, 0, tzinfo=timezone.utc)


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


def make_agent(aid="profile-agent", tags=None):
    return Agent(
        id=aid,
        hostname=f"{aid}.local",
        os_family="linux",
        os_name="Linux",
        token_hash=(aid.replace("-", "") + "x" * 64)[:64],
        tags=main.dump(tags or []),
    )


def test_profile_overrides_tag_criticality_and_exposure(db):
    agent = make_agent(tags=["lab"])
    profile = AssetRiskProfile(
        agent=agent,
        criticality_override=5,
        external_override=True,
        controls_json=main.dump(["segmented"]),
        reason="Ativo de identidade crítico",
        updated_by="user:admin",
        updated_at=REFERENCE,
    )
    db.add_all([agent, profile])
    db.commit()

    criticality = main.asset_criticality(agent)
    exposure = main.asset_exposure(agent)
    compensating = main.asset_compensating_factor(agent)

    assert criticality["score"] == 5
    assert criticality["source"] == "profile"
    assert exposure["external"] is True
    assert exposure["source"] == "profile"
    assert compensating["source"] == "profile"
    assert compensating["controls"][0]["tag"] == "segmented"


def test_null_profile_fields_fall_back_to_tags(db):
    agent = make_agent(tags=["prod", "internet-facing", "edr-protected"])
    profile = AssetRiskProfile(
        agent=agent,
        criticality_override=None,
        external_override=None,
        controls_json=None,
        reason="Sem override ativo",
        updated_by="user:admin",
        updated_at=REFERENCE,
    )
    db.add_all([agent, profile])
    db.commit()

    assert main.asset_criticality(agent)["score"] == 4
    assert main.asset_criticality(agent)["source"] == "tags"
    assert main.asset_exposure(agent)["external"] is True
    assert main.asset_exposure(agent)["source"] == "tags"
    assert main.asset_compensating_factor(agent)["source"] == "tags"


def test_empty_profile_controls_explicitly_disable_tag_controls(db):
    agent = make_agent(tags=["prod", "segmented", "edr-protected"])
    profile = AssetRiskProfile(
        agent=agent,
        controls_json=main.dump([]),
        reason="Controles não validados para este ativo",
        updated_by="user:admin",
        updated_at=REFERENCE,
    )
    db.add_all([agent, profile])
    db.commit()

    compensating = main.asset_compensating_factor(agent)

    assert compensating["source"] == "profile"
    assert compensating["controls"] == []
    assert compensating["multiplier"] == 1.0


def test_admin_update_risk_profile_is_audited(db, monkeypatch):
    agent = make_agent(tags=["lab"])
    db.add(agent)
    db.commit()

    monkeypatch.setattr(main, "capture_asset_risk_snapshots", lambda *args, **kwargs: {"created": 1})
    monkeypatch.setattr(main, "now", lambda: REFERENCE)

    result = main.update_asset_risk_profile(
        agent.id,
        AssetRiskProfileUpdate(
            criticality=5,
            external=True,
            compensating_controls=["segmented", "edr-protected"],
            reason="Ativo Tier 0 exposto externamente",
        ),
        principal={"actor": "user:admin", "role": "admin"},
        db=db,
    )

    assert result["ok"] is True
    assert result["profile"]["criticality"] == 5
    assert result["profile"]["external"] is True
    assert result["effective"]["criticality"]["source"] == "profile"

    event = db.query(AuditEvent).filter(
        AuditEvent.event_type == "asset_risk.profile.updated"
    ).one()
    assert event.actor == "user:admin"
    assert event.object_id == agent.id


def test_invalid_compensating_control_is_rejected(db):
    agent = make_agent()
    db.add(agent)
    db.commit()

    with pytest.raises(main.HTTPException) as exc:
        main.update_asset_risk_profile(
            agent.id,
            AssetRiskProfileUpdate(
                criticality=3,
                external=False,
                compensating_controls=["magic-firewall"],
                reason="Teste de controle inválido",
            ),
            principal={"actor": "user:admin", "role": "admin"},
            db=db,
        )

    assert exc.value.status_code == 400
