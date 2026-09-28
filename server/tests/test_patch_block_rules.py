import os
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi import HTTPException


TEST_DB = Path(__file__).resolve().parent / "test-patch-block-rules.db"
TEST_DB.unlink(missing_ok=True)
SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "B" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"
os.environ["THREAT_INTEL_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app import main
from app.models import Agent, Campaign, PatchBlockRule


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


def make_agent(aid="agent-1", os_family="windows", tags=None):
    return Agent(
        id=aid,
        hostname=f"{aid}.local",
        os_family=os_family,
        os_name=os_family,
        token_hash=(aid.replace("-", "") + "b" * 64)[:64],
        tags=main.dump(tags or []),
    )


def make_campaign(agent_id="agent-1"):
    return Campaign(
        id="campaign-1",
        name="Blocked campaign",
        target_os="windows",
        ring_percent=100,
        action="install_updates",
        status="draft",
        payload_json=main.dump({
            "packages": ["KB5039999"],
            "target_agent_ids": [agent_id],
        }),
    )


def make_rule(**overrides):
    values = {
        "id": "rule-1",
        "name": "Known regression",
        "patch_ref": "KB5039999",
        "target_os": "all",
        "target_tag": "",
        "reason": "Regressão confirmada no piloto",
        "enabled": True,
        "created_by": "user:admin",
        "updated_by": "user:admin",
    }
    values.update(overrides)
    return PatchBlockRule(**values)


def test_patch_guard_matches_exact_ref_os_and_tag(db):
    prod = make_agent(tags=["prod"])
    lab = make_agent(aid="agent-2", tags=["lab"])
    rule = make_rule(target_os="windows", target_tag="prod")
    db.add_all([prod, lab, rule])
    db.commit()

    assert main.patch_block_rule_matches(rule, "kb5039999", prod) is True
    assert main.patch_block_rule_matches(rule, "KB5039999", lab) is False
    assert main.patch_block_rule_matches(rule, "KB0000000", prod) is False


def test_expired_rule_is_not_active(db):
    db.add(make_rule(expires_at=main.now() - timedelta(minutes=1)))
    db.commit()

    assert main.active_patch_block_rules(db) == []


def test_deploy_fails_closed_before_jobs_are_created(db):
    agent = make_agent()
    campaign = make_campaign(agent.id)
    db.add_all([agent, campaign, make_rule()])
    db.commit()

    with pytest.raises(HTTPException) as exc:
        main.deploy_campaign(
            campaign.id,
            principal={"actor": "user:operator", "role": "operator"},
            db=db,
        )

    assert exc.value.status_code == 409
    assert exc.value.detail["message"] == "patch deployment blocked by Patch Guard"
    db.refresh(campaign)
    assert campaign.status == "draft"
    assert campaign.jobs == []
