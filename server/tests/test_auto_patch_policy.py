import os
import sys
from pathlib import Path

import pytest

TEST_DB = Path(__file__).resolve().parent / "test-auto-patch-policy.db"
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
from app.models import Agent, AssetRiskProfile, AutoPatchPolicy, Campaign, PatchApplicability, PatchBlockRule


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


def add_agent(db, agent_id="a1", external=True):
    agent = Agent(
        id=agent_id,
        hostname=agent_id + ".local",
        os_family="windows",
        os_name="Windows 11",
        token_hash="a" * 64,
        tags="[]",
    )
    db.add(agent)
    db.add(AssetRiskProfile(
        agent_id=agent_id,
        external_override=external,
        owner="ops",
        business_service="core",
        environment="prod",
        reason="test",
        updated_by="test",
    ))
    db.commit()
    return agent


def catalog_item(confidence="insufficient_data", kev=1):
    return {
        "patch_ref": "KB9999999",
        "patch_key": "kb9999999",
        "states": {"missing": 1},
        "threat": {"kev_findings": kev, "cves": ["CVE-2026-99999"]},
        "lifecycle": {"patch_tuesday": False, "eol_state": "supported"},
        "supersedence": {"obsolete": False, "preferred_replacement": None},
        "patch_confidence": {"confidence": confidence},
    }


def add_policy(db, **overrides):
    values = dict(
        id="p1",
        name="Emergency KEV",
        enabled=True,
        mode="draft",
        target_os="windows",
        target_tag="",
        require_kev=True,
        require_external=True,
        require_patch_tuesday=False,
        min_missing_assets=1,
        confidence_floor="insufficient_data",
        allow_eol=False,
        superseded_action="replace",
        ring_percent=25,
        require_approval=True,
        require_health_gate=True,
        require_rollback=True,
        created_by="user:admin",
        updated_by="user:admin",
    )
    values.update(overrides)
    policy = AutoPatchPolicy(**values)
    db.add(policy)
    db.commit()
    return policy


def test_kev_external_forces_five_percent_canary(monkeypatch, db):
    add_agent(db, external=True)
    db.add(PatchApplicability(
        id="pa1", patch_key="kb9999999", agent_id="a1",
        status="missing", evidence="agent_scan",
    ))
    add_policy(db)
    db.commit()
    monkeypatch.setattr(main, "patch_catalog_report", lambda db, limit=2000: {"items": [catalog_item()]})

    report = main.auto_patch_policy_report(db, create_drafts=False)
    decision = report["decisions"][0]
    assert decision["status"] == "draft_ready"
    assert decision["ring_percent"] == 5
    assert decision["approval_required"] is True


def test_confidence_floor_holds_draft(monkeypatch, db):
    add_agent(db, external=False)
    db.add(PatchApplicability(
        id="pa1", patch_key="kb9999999", agent_id="a1",
        status="missing", evidence="agent_scan",
    ))
    add_policy(db, require_kev=False, require_external=False, confidence_floor="high")
    db.commit()
    monkeypatch.setattr(main, "patch_catalog_report", lambda db, limit=2000: {"items": [catalog_item(confidence="low", kev=0)]})

    report = main.auto_patch_policy_report(db, create_drafts=True, actor="user:operator")
    assert report["decisions"][0]["status"] == "hold_confidence"
    assert db.query(Campaign).count() == 0


def test_patch_guard_blocks_before_draft(monkeypatch, db):
    add_agent(db, external=False)
    db.add(PatchApplicability(
        id="pa1", patch_key="kb9999999", agent_id="a1",
        status="missing", evidence="agent_scan",
    ))
    add_policy(db, require_kev=False, require_external=False)
    db.add(PatchBlockRule(
        id="r1", name="Regression", patch_ref="KB9999999",
        target_os="all", target_tag="", reason="Known regression",
        enabled=True, created_by="user:admin", updated_by="user:admin",
    ))
    db.commit()
    monkeypatch.setattr(main, "patch_catalog_report", lambda db, limit=2000: {"items": [catalog_item(kev=0)]})

    report = main.auto_patch_policy_report(db, create_drafts=True, actor="user:operator")
    assert report["decisions"][0]["status"] == "blocked_patch_guard"
    assert db.query(Campaign).count() == 0


def test_draft_creation_is_deduplicated(monkeypatch, db):
    add_agent(db, external=False)
    db.add(PatchApplicability(
        id="pa1", patch_key="kb9999999", agent_id="a1",
        status="missing", evidence="agent_scan",
    ))
    add_policy(db, require_kev=False, require_external=False)
    db.commit()
    monkeypatch.setattr(main, "patch_catalog_report", lambda db, limit=2000: {"items": [catalog_item(kev=0)]})

    first = main.auto_patch_policy_report(db, create_drafts=True, actor="user:operator")
    second = main.auto_patch_policy_report(db, create_drafts=True, actor="user:operator")
    assert first["summary"]["drafts_created"] == 1
    assert second["summary"]["drafts_created"] == 0
    assert second["decisions"][0]["status"] == "draft_exists"
    assert db.query(Campaign).count() == 1
