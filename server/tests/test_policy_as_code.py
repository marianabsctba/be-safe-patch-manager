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


def test_policy_bundle_round_trip_and_integrity(db):
    item = campaign(db, ring=10)
    normalized = main.validate_patch_policy_document(document(max_ring=10))
    db.add(PatchPolicyDefinition(
        id="bundle-p1", name="Tier0 Bundle", version=1, enabled=True, priority=200,
        policy_json=main.dump(normalized), policy_sha256=main._evidence_sha256(normalized),
        created_by="admin",
    ))
    db.commit()

    bundle = main.build_patch_policy_bundle(db)
    validated = main.validate_patch_policy_bundle(bundle)

    assert validated["valid"] is True
    assert validated["policy_count"] == 1
    assert len(validated["bundle_sha256"]) == 64


def test_policy_bundle_detects_tampering(db):
    normalized = main.validate_patch_policy_document(document(max_ring=10))
    db.add(PatchPolicyDefinition(
        id="bundle-p1", name="Tier0 Bundle", version=1, enabled=True, priority=200,
        policy_json=main.dump(normalized), policy_sha256=main._evidence_sha256(normalized),
        created_by="admin",
    ))
    db.commit()

    bundle = main.build_patch_policy_bundle(db)
    bundle["policies"][0]["policy"]["requirements"]["max_initial_ring_percent"] = 100

    with pytest.raises(Exception):
        main.validate_patch_policy_bundle(bundle)


def test_policy_bundle_dry_run_finds_newly_blocked_campaign(db):
    item = campaign(db, ring=10)
    proposed = main.validate_patch_policy_document(document(max_ring=5))
    content = {
        "schema": "be-safe-patch-policy-bundle/v1",
        "generated_at": "2026-09-29T00:00:00+00:00",
        "policies": [{
            "name": "Tier0 Proposed",
            "version": 1,
            "priority": 100,
            "enabled": True,
            "policy": proposed,
            "policy_sha256": main._evidence_sha256(proposed),
        }],
    }
    bundle = {
        **content,
        "manifest": {
            "hash_algorithm": "SHA-256",
            "bundle_sha256": main._evidence_sha256(content),
            "policy_count": 1,
        },
    }

    impact = main.patch_policy_bundle_impact(db, bundle)

    assert impact["summary"]["newly_blocked"] == 1
    assert impact["campaigns"][0]["campaign_id"] == item.id


def test_policy_bundle_import_versions_changed_policy(db):
    campaign(db, ring=10)
    old = main.validate_patch_policy_document(document(max_ring=10))
    db.add(PatchPolicyDefinition(
        id="import-p1", name="Tier0 Import", version=1, enabled=True, priority=100,
        policy_json=main.dump(old), policy_sha256=main._evidence_sha256(old), created_by="admin",
    ))
    db.commit()

    new = main.validate_patch_policy_document(document(max_ring=5))
    content = {
        "schema": "be-safe-patch-policy-bundle/v1",
        "generated_at": "2026-09-29T00:00:00+00:00",
        "policies": [{
            "name": "Tier0 Import",
            "version": 9,
            "priority": 100,
            "enabled": True,
            "policy": new,
            "policy_sha256": main._evidence_sha256(new),
        }],
    }
    bundle = {
        **content,
        "manifest": {
            "hash_algorithm": "SHA-256",
            "bundle_sha256": main._evidence_sha256(content),
            "policy_count": 1,
        },
    }

    result = main.import_patch_policy_bundle(db, bundle, "user:admin")

    assert len(result["created"]) == 1
    assert result["created"][0]["version"] == 2
    assert result["created"][0]["supersedes_id"] == "import-p1"


def test_policy_waiver_suppresses_enforcement_but_preserves_violation(db):
    item = campaign(db, ring=10)
    normalized = main.validate_patch_policy_document(document(max_ring=5))
    policy = PatchPolicyDefinition(
        id="waiver-p1", name="Tier0 Waiver", version=1, enabled=True, priority=100,
        policy_json=main.dump(normalized), policy_sha256=main._evidence_sha256(normalized),
        created_by="admin",
    )
    db.add(policy)
    db.commit()

    from app.models import PatchPolicyWaiver
    from datetime import datetime, timedelta, timezone
    waiver = PatchPolicyWaiver(
        id="w1",
        campaign_id=item.id,
        policy_id=policy.id,
        policy_sha256=policy.policy_sha256,
        reason="Approved temporary exception for controlled maintenance",
        approved_by="user:admin",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=6),
    )
    db.add(waiver)
    db.commit()

    report = main.campaign_policy_as_code_report(db, item)

    assert report["blocking"] is False
    assert len(report["waived_violations"]) == 1
    assert report["evaluations"][0]["violations"][0]["waived"] is True


def test_policy_waiver_does_not_survive_policy_digest_change(db):
    item = campaign(db, ring=10)
    normalized = main.validate_patch_policy_document(document(max_ring=5))
    policy = PatchPolicyDefinition(
        id="waiver-p1", name="Tier0 Waiver", version=1, enabled=True, priority=100,
        policy_json=main.dump(normalized), policy_sha256=main._evidence_sha256(normalized),
        created_by="admin",
    )
    db.add(policy)
    db.commit()

    from app.models import PatchPolicyWaiver
    from datetime import datetime, timedelta, timezone
    db.add(PatchPolicyWaiver(
        id="w1", campaign_id=item.id, policy_id=policy.id,
        policy_sha256="0" * 64,
        reason="Old exception", approved_by="user:admin",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=6),
    ))
    db.commit()

    report = main.campaign_policy_as_code_report(db, item)

    assert report["blocking"] is True
    assert report["waived_violations"] == []
