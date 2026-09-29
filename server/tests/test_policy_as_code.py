import os
import sys
from pathlib import Path

import pytest

TEST_DB = Path(__file__).resolve().parent / "test-policy-as-code.db"
TEST_DB.unlink(missing_ok=True)
SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "Q" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"
os.environ["THREAT_INTEL_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app import main
from app.models import Agent, AssetRiskProfile, Campaign, PatchPolicyDefinition


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


def campaign(db, ring=10, health=True, rollback=True, window=True):
    agent = Agent(
        id="tier0-a",
        hostname="tier0-a.local",
        os_family="windows",
        os_name="Windows Server",
        token_hash="z" * 64,
        tags='["tier0"]',
    )
    db.add(agent)
    db.flush()
    db.add(AssetRiskProfile(
        agent_id=agent.id,
        criticality_override=5,
        owner="iam",
        business_service="identity",
        environment="production",
        updated_by="test",
    ))
    db.commit()
    baseline = main.build_scope_baseline([agent])
    item = Campaign(
        id="c-policy",
        name="Tier0 policy test",
        target_os="windows",
        target_tag="tier0",
        ring_percent=ring,
        action="install_updates",
        payload_json=main.dump({
            "scope_baseline": baseline,
            "packages": ["KB1"],
            "health_policy": {"enabled": health},
            "prepare_rollback": rollback,
            "maintenance_start": "22:00" if window else "",
            "maintenance_end": "23:00" if window else "",
            "approval_required": False,
        }),
        status="draft",
    )
    db.add(item)
    db.commit()
    return item


def document(max_ring=5):
    return {
        "schema": "be-safe-patch-policy/v1",
        "description": "Tier 0 production",
        "match": {
            "actions": ["install_updates"],
            "target_os": ["windows"],
            "tags_any": ["tier0"],
            "environments": ["production"],
            "min_criticality": 4,
        },
        "requirements": {
            "max_initial_ring_percent": max_ring,
            "require_health_gate": True,
            "require_rollback": True,
            "require_maintenance_window": True,
            "min_approvals": 0,
        },
    }


def test_policy_simulation_explains_ring_violation(db):
    item = campaign(db, ring=10)
    result = main.evaluate_patch_policy_document(item, document(max_ring=5))
    assert result["matched"] is True
    assert result["compliant"] is False
    assert result["violations"][0]["key"] == "max_initial_ring_percent"


def test_policy_report_blocks_applicable_violation(db):
    item = campaign(db, ring=10)
    normalized = main.validate_patch_policy_document(document(max_ring=5))
    db.add(PatchPolicyDefinition(
        id="p1", name="Tier0", version=1, enabled=True, priority=100,
        policy_json=main.dump(normalized), policy_sha256=main._evidence_sha256(normalized),
        created_by="user:admin",
    ))
    db.commit()
    result = main.campaign_policy_as_code_report(db, item)
    assert result["blocking"] is True
    assert result["matched_policies"] == 1


def test_policy_version_latest_enabled_wins(db):
    item = campaign(db, ring=10)
    old = main.validate_patch_policy_document(document(max_ring=5))
    new = main.validate_patch_policy_document(document(max_ring=10))
    db.add(PatchPolicyDefinition(
        id="p1", name="Tier0", version=1, enabled=True, priority=100,
        policy_json=main.dump(old), policy_sha256=main._evidence_sha256(old), created_by="admin",
    ))
    db.add(PatchPolicyDefinition(
        id="p2", name="Tier0", version=2, enabled=True, priority=100,
        policy_json=main.dump(new), policy_sha256=main._evidence_sha256(new),
        supersedes_id="p1", created_by="admin",
    ))
    db.commit()
    result = main.campaign_policy_as_code_report(db, item)
    assert result["blocking"] is False
    assert result["evaluations"][0]["version"] == 2


def test_policy_nonmatching_scope_does_not_block(db):
    item = campaign(db, ring=100, health=False, rollback=False, window=False)
    doc = document()
    doc["match"]["target_os"] = ["linux"]
    result = main.evaluate_patch_policy_document(item, doc)
    assert result["matched"] is False
    assert result["compliant"] is True
