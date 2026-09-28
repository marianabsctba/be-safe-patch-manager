import os
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException


TEST_DB = Path(__file__).resolve().parent / "test-campaign-approval.db"
TEST_DB.unlink(missing_ok=True)
SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "A" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"
os.environ["THREAT_INTEL_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app import main
from app.models import Agent
from app.schemas import CampaignApprovalDecision, CampaignCreate


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


def agent():
    return Agent(
        id="approval-agent",
        hostname="approval.local",
        os_family="windows",
        os_name="Windows",
        token_hash="a" * 64,
        tags="[]",
    )


def create_protected_campaign(db, actor="user:operator"):
    db.add(agent())
    db.commit()
    return main.create_campaign(
        CampaignCreate(
            name="Protected patch",
            target_os="windows",
            ring_percent=100,
            action="install_updates",
            payload={"packages": ["KB-APPROVAL"]},
            target_agent_ids=["approval-agent"],
            approval_required=True,
            approval_reason="Mudança sensível em produção",
        ),
        principal={"actor": actor, "role": "admin" if actor == "user:admin" else "operator"},
        db=db,
    )


def test_pending_approval_blocks_deploy(db):
    created = create_protected_campaign(db)

    with pytest.raises(HTTPException) as exc:
        main.deploy_campaign(
            created["id"],
            principal={"actor": "user:operator", "role": "operator"},
            db=db,
        )

    assert exc.value.status_code == 409
    assert exc.value.detail["approval"]["status"] == "pending"


def test_second_actor_can_approve_then_deploy(db):
    created = create_protected_campaign(db)

    approved = main.approve_campaign(
        created["id"],
        CampaignApprovalDecision(reason="Revisado e aprovado para a janela"),
        principal={"actor": "user:admin", "role": "admin"},
        db=db,
    )
    assert approved["campaign"]["approval"]["status"] == "approved"

    deployed = main.deploy_campaign(
        created["id"],
        principal={"actor": "user:operator", "role": "operator"},
        db=db,
    )
    assert deployed["campaign"]["status"] == "deployed"
    assert deployed["agents_selected"] == 1


def test_requester_cannot_self_approve(db):
    created = create_protected_campaign(db, actor="user:admin")

    with pytest.raises(HTTPException) as exc:
        main.approve_campaign(
            created["id"],
            CampaignApprovalDecision(reason="Tentativa de auto aprovação"),
            principal={"actor": "user:admin", "role": "admin"},
            db=db,
        )

    assert exc.value.status_code == 409
    assert "cannot approve" in str(exc.value.detail)
