import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

TEST_DB = Path(__file__).resolve().parent / "test-rollout-governance.db"
TEST_DB.unlink(missing_ok=True)
SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "R" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"
os.environ["THREAT_INTEL_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app import main
from app.models import Agent, Campaign, CampaignRingDecision, PatchJob


@pytest.fixture(autouse=True)
def clean_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db():
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()


def build_campaign(db, *, ring=10, soak=60, min_success=90, pause=True, statuses=None, finished_delta=120):
    statuses = statuses or ["success"]
    campaign = Campaign(
        id="c1",
        name="Progressive",
        target_os="windows",
        target_tag="",
        ring_percent=ring,
        action="install_updates",
        payload_json=main.dump({
            "post_patch_validation": False,
            "health_policy": {"enabled": False},
            "rollout_governance": {
                "plan": [10, 30, 100],
                "soak_minutes": soak,
                "promotion_min_success_rate": min_success,
                "pause_on_failure": pause,
            },
        }),
        status="deployed",
    )
    db.add(campaign)
    for idx, status in enumerate(statuses):
        agent = Agent(
            id=f"a{idx}",
            hostname=f"a{idx}.local",
            os_family="windows",
            os_name="Windows",
            token_hash=(f"token-{idx}-" + "x"*64)[:64],
            tags="[]",
        )
        db.add(agent)
        db.add(PatchJob(
            id=f"j{idx}",
            campaign_id="c1",
            agent_id=agent.id,
            action="install_updates",
            payload_json=main.dump({"_ring_percent": ring, "post_patch_validation": False}),
            status=status,
            finished_at=datetime.now(timezone.utc) - timedelta(minutes=finished_delta),
            result_json="{}",
        ))
    db.commit()
    return db.get(Campaign, "c1")


def test_rollout_promote_after_soak(db):
    c = build_campaign(db, soak=60, finished_delta=120)
    state = main.campaign_rollout_governance(c)
    assert state["state"] == "PROMOTE"
    assert state["next_ring"] == 30


def test_rollout_waits_during_soak(db):
    c = build_campaign(db, soak=60, finished_delta=10)
    state = main.campaign_rollout_governance(c)
    assert state["state"] == "SOAK"
    assert state["soak_remaining_seconds"] > 0


def test_rollout_pauses_on_failure(db):
    c = build_campaign(db, statuses=["success", "failed"], min_success=50, pause=True)
    state = main.campaign_rollout_governance(c)
    assert state["state"] == "PAUSE"


def test_rollout_complete_at_100(db):
    c = build_campaign(db, ring=100, soak=0, statuses=["success"])
    state = main.campaign_rollout_governance(c)
    assert state["state"] == "COMPLETE"
    assert state["next_ring"] is None


def test_configured_success_threshold_is_used(db):
    c = build_campaign(db, statuses=["success", "failed"], min_success=50, pause=False, soak=0)
    health = main.campaign_health(c)
    assert health["required_success_rate"] == 50.0
    assert health["ready"] is True


def test_ring_decision_serialization(db):
    c = build_campaign(db)
    entry = main.record_campaign_ring_decision(
        db, c, 10, 30, "PROMOTE", "healthy", main.campaign_health(c), "user:operator"
    )
    db.commit()
    assert db.query(CampaignRingDecision).count() == 1
    data = main.serialize_campaign_ring_decision(entry)
    assert data["from_ring"] == 10
    assert data["to_ring"] == 30
    assert data["decision"] == "PROMOTE"
