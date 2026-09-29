import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

TEST_DB = Path(__file__).resolve().parent / "test-campaign-preflight.db"
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
from app.models import Agent, AssetRiskProfile, Campaign, CampaignApproval, CampaignPreflightSnapshot, PatchApplicability, PatchBlockRule, PatchCatalogEntry, PatchJob


@pytest.fixture(autouse=True)
def clean_database(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(main, "AGENT_ENFORCE_COMPATIBILITY", True)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def make_agent(db, agent_id="a1", capabilities=None):
    capabilities = capabilities or [
        "job_leases_v1",
        "install_updates",
        "rollback_checkpoint_v1",
        "health_telemetry_v1",
    ]
    agent = Agent(
        id=agent_id,
        hostname=f"{agent_id}.local",
        os_family="windows",
        os_name="Windows Server 2022",
        token_hash=(agent_id + "-" + "x" * 64)[:64],
        tags='["tier0"]',
        last_seen=datetime.now(timezone.utc),
        inventory_json=main.dump({
            "agent": {
                "version": main.AGENT_MIN_VERSION,
                "protocol": main.AGENT_MIN_PROTOCOL,
                "capabilities": capabilities,
            }
        }),
    )
    db.add(agent)
    db.commit()
    return agent


def make_campaign(db, *, approval_required=False, payload_extra=None):
    payload = {
        "packages": ["KB5072198"],
        "prepare_rollback": True,
        "rollback_required": True,
        "health_policy": {"enabled": True, "required": True},
        "approval_required": approval_required,
        "maintenance_start": "",
        "maintenance_end": "",
        "maintenance_timezone": "America/Sao_Paulo",
        "maintenance_days": list(range(7)),
    }
    payload.update(payload_extra or {})
    campaign = Campaign(
        id="c1",
        name="Tier0 September",
        target_os="windows",
        target_tag="tier0",
        ring_percent=10,
        action="install_updates",
        payload_json=main.dump(payload),
        status="draft",
    )
    db.add(campaign)
    db.commit()
    return db.get(Campaign, "c1")


def check(report, key):
    return next(item for item in report["checks"] if item["key"] == key)


def test_preflight_ready_with_supported_agent(db):
    make_agent(db)
    campaign = make_campaign(db)
    report = main.campaign_preflight(db, campaign)

    assert report["deploy_allowed"] is True
    assert report["readiness"] in {"READY", "REVIEW"}
    assert check(report, "scope")["status"] == "passed"
    assert check(report, "agent_compatibility")["status"] == "passed"
    assert check(report, "patch_guard")["status"] == "passed"


def test_preflight_blocks_missing_approval(db):
    make_agent(db)
    campaign = make_campaign(db, approval_required=True)
    db.add(CampaignApproval(
        id="ap1",
        campaign_id=campaign.id,
        status="pending",
        request_reason="Tier0 change",
        requested_by="user:operator",
    ))
    db.commit()

    report = main.campaign_preflight(db, campaign)
    approval = check(report, "approval")

    assert report["readiness"] == "BLOCKED"
    assert report["deploy_allowed"] is False
    assert approval["blocking"] is True


def test_preflight_blocks_patch_guard(db):
    make_agent(db)
    campaign = make_campaign(db)
    db.add(PatchBlockRule(
        id="r1",
        name="Known regression",
        patch_ref="KB5072198",
        target_os="windows",
        target_tag="tier0",
        reason="pilot regression",
        enabled=True,
        created_by="user:admin",
        updated_by="user:admin",
    ))
    db.commit()

    report = main.campaign_preflight(db, campaign)
    guard = check(report, "patch_guard")

    assert report["deploy_allowed"] is False
    assert guard["status"] == "blocked"
    assert guard["details"]["blockers"][0]["matched_assets"] == 1


def test_preflight_blocks_incompatible_agent_when_enforced(db):
    make_agent(db, capabilities=["job_leases_v1", "install_updates"])
    campaign = make_campaign(db)

    report = main.campaign_preflight(db, campaign)
    compatibility = check(report, "agent_compatibility")

    assert compatibility["status"] == "blocked"
    assert compatibility["blocking"] is True
    assert report["deploy_allowed"] is False


def test_preflight_warns_on_stale_heartbeat(db):
    agent = make_agent(db)
    agent.last_seen = datetime.now(timezone.utc) - timedelta(hours=2)
    db.commit()
    campaign = make_campaign(db)

    report = main.campaign_preflight(db, campaign)
    heartbeat = check(report, "heartbeat")

    assert heartbeat["status"] == "warning"
    assert heartbeat["blocking"] is False
    assert report["readiness"] == "REVIEW"



def test_preflight_snapshot_is_immutable_hashed_evidence(db):
    make_agent(db)
    campaign = make_campaign(db)
    result = main.campaign_preflight(db, campaign)

    snapshot = main.persist_campaign_preflight_snapshot(
        db, campaign, result, "user:operator", "manual"
    )

    assert db.query(CampaignPreflightSnapshot).count() == 1
    assert snapshot.readiness == result["readiness"]
    assert snapshot.actor == "user:operator"
    assert snapshot.source == "manual"
    assert len(snapshot.result_sha256) == 64
    assert main.load(snapshot.result_json, {})["campaign_id"] == campaign.id


def test_preflight_drift_detects_degradation():
    previous = {
        "checks": [
            {"key": "heartbeat", "label": "Agent freshness", "status": "passed", "message": "recent"},
            {"key": "patch_guard", "label": "Patch Guard", "status": "passed", "message": "clear"},
        ]
    }
    current = {
        "checks": [
            {"key": "heartbeat", "label": "Agent freshness", "status": "warning", "message": "stale"},
            {"key": "patch_guard", "label": "Patch Guard", "status": "blocked", "message": "rule matched"},
        ]
    }

    drift = main.campaign_preflight_drift(previous, current)

    assert drift["status"] == "DEGRADED"
    assert drift["degraded"] == 2
    assert {item["key"] for item in drift["changes"]} == {"heartbeat", "patch_guard"}


def test_preflight_drift_reports_unchanged():
    result = {
        "checks": [
            {"key": "scope", "label": "Target scope", "status": "passed", "message": "10 endpoints"}
        ]
    }

    drift = main.campaign_preflight_drift(result, result)

    assert drift["status"] == "UNCHANGED"
    assert drift["changed"] is False
    assert drift["changes"] == []


def test_deploy_attempt_persists_preflight_snapshot(db):
    make_agent(db)
    campaign = make_campaign(db)

    result = main.deploy_campaign(
        campaign.id,
        principal={"actor": "user:operator", "role": "operator"},
        db=db,
    )

    snapshots = db.query(CampaignPreflightSnapshot).filter(
        CampaignPreflightSnapshot.campaign_id == campaign.id
    ).all()
    assert len(snapshots) == 1
    assert snapshots[0].source == "deploy_attempt"
    assert result["preflight_snapshot"]["id"] == snapshots[0].id
    assert result["preflight_drift"]["status"] == "NO_BASELINE"



def test_campaign_evidence_pack_hashes_sections_and_pack(db):
    make_agent(db)
    campaign = make_campaign(db)

    main.deploy_campaign(
        campaign.id,
        principal={"actor": "user:operator", "role": "operator"},
        db=db,
    )

    pack = main.campaign_evidence_pack(db, campaign)

    assert pack["schema"] == "be-safe-campaign-evidence-pack/v1"
    assert pack["summary"]["jobs"] == 1
    assert pack["summary"]["preflight_snapshots"] == 1
    assert len(pack["manifest"]["pack_sha256"]) == 64
    assert set(pack["manifest"]["section_hashes"]) == {
        "campaign",
        "approval",
        "blast_radius",
        "ring_plan",
        "change_collisions",
        "patch_applicability",
        "preflight_snapshots",
        "ring_decisions",
        "jobs",
        "freeze_override",
        "audit_events",
    }

    for key, value in pack["sections"].items():
        assert pack["manifest"]["section_hashes"][key] == main._evidence_sha256(value)

    content = {key: value for key, value in pack.items() if key != "manifest"}
    assert pack["manifest"]["pack_sha256"] == main._evidence_sha256(content)


def test_campaign_evidence_pack_preserves_job_health_and_rollback_evidence(db):
    make_agent(db)
    campaign = make_campaign(db)
    result = main.deploy_campaign(
        campaign.id,
        principal={"actor": "user:operator", "role": "operator"},
        db=db,
    )
    db.refresh(campaign)
    job = campaign.jobs[0]
    job.status = "success"
    job.started_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    job.finished_at = datetime.now(timezone.utc)
    job.result_json = main.dump({
        "validation": {"ok": True},
        "health_validation": {"ok": True, "issues": []},
        "rollback": {"checkpoint_id": "cp-123"},
    })
    db.commit()

    pack = main.campaign_evidence_pack(db, campaign)
    exported = pack["sections"]["jobs"][0]

    assert exported["status"] == "success"
    assert "validation" in exported
    assert "rollback" in exported
    assert exported["campaign_id"] == result["campaign"]["id"]



def seed_failed_patch_history(db, agent, *, failures=3, patch_ref="KB5072198", error="installer failed with exit code 1603"):
    historical = Campaign(
        id="history-campaign",
        name="Historical failed rollout",
        target_os="windows",
        target_tag="tier0",
        ring_percent=100,
        action="install_updates",
        payload_json=main.dump({"packages": [patch_ref]}),
        status="deployed",
    )
    db.add(historical)
    db.flush()
    stamp = datetime.now(timezone.utc) - timedelta(days=1)
    for index in range(failures):
        db.add(PatchJob(
            id=f"failed-{index}",
            campaign_id=historical.id,
            agent_id=agent.id,
            action="install_updates",
            payload_json=main.dump({"packages": [patch_ref]}),
            status="failed",
            error=error,
            started_at=stamp,
            finished_at=stamp + timedelta(minutes=2),
            created_at=stamp,
        ))
    db.commit()
    return historical


def test_failure_intelligence_confirms_local_regression(db):
    agent = make_agent(db)
    seed_failed_patch_history(db, agent)

    report = main.patch_failure_intelligence_report(db, lookback_days=30)

    assert report["summary"]["confirmed_local_regressions"] == 1
    item = report["patches"][0]
    assert item["patch_ref"] == "KB5072198"
    assert item["regression_state"] == "confirmed_local_regression"
    assert item["effective_failure_rate"] == 100.0
    assert item["failed"] == 3
    assert report["clusters"][0]["category"] == "install_failure"
    assert report["clusters"][0]["count"] == 3


def test_failure_signature_normalizes_volatile_values():
    a = main.normalize_failure_signature("Download timeout https://repo.local/a 0x80070005 code 123456")
    b = main.normalize_failure_signature("Download timeout https://repo.local/b 0x80072efe code 987654")

    assert a == b
    assert "<url>" in a
    assert "<hex>" in a
    assert "<n>" in a


def test_preflight_blocks_confirmed_matching_local_regression(db):
    agent = make_agent(db)
    seed_failed_patch_history(db, agent)
    campaign = make_campaign(db)

    report = main.campaign_preflight(db, campaign)
    regression = check(report, "local_regression")

    assert regression["status"] == "blocked"
    assert regression["blocking"] is True
    assert regression["details"]["state"] == "confirmed_local_regression"
    assert report["readiness"] == "BLOCKED"
    assert report["deploy_allowed"] is False


def test_preflight_does_not_apply_regression_from_other_patch(db):
    agent = make_agent(db)
    seed_failed_patch_history(db, agent, patch_ref="KB0000001")
    campaign = make_campaign(db)

    report = main.campaign_preflight(db, campaign)
    regression = check(report, "local_regression")

    assert regression["status"] == "passed"
    assert regression["blocking"] is False



def test_blast_radius_reuses_business_context_and_risk(db):
    a1 = make_agent(db, "a1")
    a2 = make_agent(db, "a2")
    a3 = make_agent(db, "a3")
    db.add_all([
        AssetRiskProfile(
            agent_id=a1.id,
            criticality_override=5,
            external_override=True,
            owner="soc-owner",
            business_service="identity",
            environment="prod",
            updated_by="user:admin",
        ),
        AssetRiskProfile(
            agent_id=a2.id,
            criticality_override=4,
            external_override=False,
            owner="soc-owner",
            business_service="identity",
            environment="prod",
            updated_by="user:admin",
        ),
        AssetRiskProfile(
            agent_id=a3.id,
            criticality_override=2,
            external_override=False,
            owner="app-owner",
            business_service="erp",
            environment="prod",
            updated_by="user:admin",
        ),
    ])
    db.commit()

    campaign = make_campaign(db, payload_extra={"target_agent_ids": ["a1", "a2", "a3"]})
    campaign.ring_percent = 100
    db.commit()

    report = main.campaign_blast_radius(db, campaign)

    assert report["summary"]["ring_assets"] == 3
    assert report["summary"]["critical_assets"] == 2
    assert report["summary"]["external_assets"] == 1
    assert report["summary"]["top_business_service"]["name"] == "identity"
    assert report["summary"]["top_business_service"]["percent"] == 66.7
    assert report["impact_state"] == "critical_scope"


def test_blast_radius_warns_preflight_without_becoming_hidden_blocker(db):
    agent = make_agent(db)
    db.add(AssetRiskProfile(
        agent_id=agent.id,
        criticality_override=5,
        external_override=False,
        owner="",
        business_service="identity",
        environment="prod",
        updated_by="user:admin",
    ))
    db.commit()
    campaign = make_campaign(db)

    report = main.campaign_preflight(db, campaign)
    blast = check(report, "blast_radius")

    assert blast["status"] == "warning"
    assert blast["blocking"] is False
    assert blast["details"]["impact_state"] == "critical_scope"


def test_blast_radius_is_included_in_evidence_pack(db):
    make_agent(db)
    campaign = make_campaign(db)

    pack = main.campaign_evidence_pack(db, campaign)

    assert "blast_radius" in pack["sections"]
    assert "blast_radius" in pack["manifest"]["section_hashes"]
    assert pack["manifest"]["section_hashes"]["blast_radius"] == main._evidence_sha256(
        pack["sections"]["blast_radius"]
    )



def test_balanced_ring_planner_is_deterministic_and_context_diverse(db):
    agents = [make_agent(db, f"a{index}") for index in range(1, 7)]
    profiles = [
        ("svc-a", "prod", "owner-a", 2),
        ("svc-a", "prod", "owner-a", 5),
        ("svc-b", "prod", "owner-b", 2),
        ("svc-b", "stage", "owner-b", 4),
        ("svc-c", "stage", "owner-c", 2),
        ("svc-c", "dev", "owner-c", 2),
    ]
    for agent, (service, environment, owner, criticality) in zip(agents, profiles):
        db.add(AssetRiskProfile(
            agent_id=agent.id,
            criticality_override=criticality,
            external_override=False,
            owner=owner,
            business_service=service,
            environment=environment,
            updated_by="user:admin",
        ))
    db.commit()

    campaign = make_campaign(db, payload_extra={
        "target_agent_ids": [agent.id for agent in agents],
        "ring_strategy": "balanced",
        "canary_max_critical_percent": 25,
    })
    campaign.ring_percent = 50
    db.commit()

    first = main.campaign_ring_plan(db, campaign)
    second = main.campaign_ring_plan(db, campaign)

    assert first["strategy"] == "balanced"
    assert first["target_count"] == 3
    assert first["selected_count"] == 3
    assert [item["agent_id"] for item in first["selection"]] == [
        item["agent_id"] for item in second["selection"]
    ]
    assert first["coverage"]["business_services"] >= 2
    assert first["coverage"]["environments"] >= 2
    assert first["critical_selected"] <= 1


def test_balanced_ring_planner_uses_critical_asset_when_no_alternative(db):
    agents = [make_agent(db, f"c{index}") for index in range(1, 4)]
    for agent in agents:
        db.add(AssetRiskProfile(
            agent_id=agent.id,
            criticality_override=5,
            external_override=False,
            owner="identity-owner",
            business_service="identity",
            environment="prod",
            updated_by="user:admin",
        ))
    db.commit()

    campaign = make_campaign(db, payload_extra={
        "target_agent_ids": [agent.id for agent in agents],
        "ring_strategy": "balanced",
        "canary_max_critical_percent": 0,
    })
    campaign.ring_percent = 34
    db.commit()

    plan = main.campaign_ring_plan(db, campaign)

    assert plan["target_count"] == 2
    assert plan["critical_selected"] == 2
    assert len(plan["selection"]) == 2


def test_preflight_exposes_smart_canary_evidence(db):
    agents = [make_agent(db, f"s{index}") for index in range(1, 5)]
    for index, agent in enumerate(agents, start=1):
        db.add(AssetRiskProfile(
            agent_id=agent.id,
            criticality_override=2,
            external_override=False,
            owner=f"owner-{index % 2}",
            business_service=f"svc-{index % 2}",
            environment="prod" if index % 2 else "stage",
            updated_by="user:admin",
        ))
    db.commit()
    campaign = make_campaign(db, payload_extra={
        "target_agent_ids": [agent.id for agent in agents],
        "ring_strategy": "balanced",
        "canary_max_critical_percent": 25,
    })
    campaign.ring_percent = 50
    db.commit()

    report = main.campaign_preflight(db, campaign)
    smart = check(report, "smart_canary")

    assert smart["status"] == "passed"
    assert smart["details"]["strategy"] == "balanced"
    assert smart["details"]["selected_count"] == 2


def test_evidence_pack_includes_ring_plan_hash(db):
    make_agent(db)
    campaign = make_campaign(db, payload_extra={"ring_strategy": "balanced"})

    pack = main.campaign_evidence_pack(db, campaign)

    assert "ring_plan" in pack["sections"]
    assert pack["manifest"]["section_hashes"]["ring_plan"] == main._evidence_sha256(
        pack["sections"]["ring_plan"]
    )



def test_change_collision_blocks_same_endpoint_with_active_job(db):
    agent = make_agent(db, "collision-agent")
    current = make_campaign(db, payload_extra={"target_agent_ids": [agent.id]})
    other = Campaign(
        id="other-campaign",
        name="Other rollout",
        target_os="windows",
        target_tag="tier0",
        ring_percent=100,
        action="install_updates",
        payload_json=main.dump({"target_agent_ids": [agent.id], "packages": ["KB1"]}),
        status="deployed",
    )
    db.add(other)
    db.flush()
    db.add(PatchJob(
        id="other-job",
        campaign_id=other.id,
        agent_id=agent.id,
        action="install_updates",
        payload_json=main.dump({"packages": ["KB1"]}),
        status="running",
    ))
    db.commit()

    report = main.campaign_change_collisions(db, current)
    assert report["state"] == "direct_collision"
    assert report["blocking"] is True
    assert report["summary"]["direct_asset_collisions"] == 1

    preflight = main.campaign_preflight(db, current)
    collision = check(preflight, "change_collision")
    assert collision["status"] == "blocked"
    assert collision["blocking"] is True


def test_change_collision_warns_on_shared_service_environment(db):
    a1 = make_agent(db, "current-agent")
    a2 = make_agent(db, "other-agent")
    db.add_all([
        AssetRiskProfile(
            agent_id=a1.id, criticality_override=2, external_override=False,
            owner="identity-owner", business_service="identity", environment="prod",
            updated_by="user:admin",
        ),
        AssetRiskProfile(
            agent_id=a2.id, criticality_override=2, external_override=False,
            owner="identity-owner", business_service="identity", environment="prod",
            updated_by="user:admin",
        ),
    ])
    db.commit()

    current = make_campaign(db, payload_extra={"target_agent_ids": [a1.id]})
    other = Campaign(
        id="other-context-campaign",
        name="Concurrent identity rollout",
        target_os="windows",
        target_tag="tier0",
        ring_percent=100,
        action="install_updates",
        payload_json=main.dump({"target_agent_ids": [a2.id], "packages": ["KB2"]}),
        status="deployed",
    )
    db.add(other)
    db.flush()
    db.add(PatchJob(
        id="other-context-job",
        campaign_id=other.id,
        agent_id=a2.id,
        action="install_updates",
        payload_json=main.dump({"packages": ["KB2"]}),
        status="running",
    ))
    db.commit()

    report = main.campaign_change_collisions(db, current)
    assert report["state"] == "context_collision"
    assert report["blocking"] is False
    assert report["summary"]["shared_service_environment_segments"] == 1

    preflight = main.campaign_preflight(db, current)
    collision = check(preflight, "change_collision")
    assert collision["status"] == "warning"
    assert collision["blocking"] is False


def test_change_collision_ignores_terminal_jobs(db):
    agent = make_agent(db, "terminal-agent")
    current = make_campaign(db, payload_extra={"target_agent_ids": [agent.id]})
    other = Campaign(
        id="terminal-campaign",
        name="Completed rollout",
        target_os="windows",
        target_tag="tier0",
        ring_percent=100,
        action="install_updates",
        payload_json=main.dump({"target_agent_ids": [agent.id], "packages": ["KB3"]}),
        status="deployed",
    )
    db.add(other)
    db.flush()
    db.add(PatchJob(
        id="terminal-job",
        campaign_id=other.id,
        agent_id=agent.id,
        action="install_updates",
        payload_json=main.dump({"packages": ["KB3"]}),
        status="success",
    ))
    db.commit()

    report = main.campaign_change_collisions(db, current)
    assert report["state"] == "clear"
    assert report["blocking"] is False


def test_evidence_pack_includes_change_collision_hash(db):
    make_agent(db)
    campaign = make_campaign(db)

    pack = main.campaign_evidence_pack(db, campaign)

    assert "change_collisions" in pack["sections"]
    assert pack["manifest"]["section_hashes"]["change_collisions"] == main._evidence_sha256(
        pack["sections"]["change_collisions"]
    )



def test_applicability_guard_blocks_superseded_patch_with_known_replacement(db):
    agent = make_agent(db, "superseded-agent")
    old = PatchCatalogEntry(
        patch_key="kb-old",
        patch_ref="KB-OLD",
        vendor="microsoft",
        product="windows",
        title="Old cumulative update",
        severity="high",
        supersedes_json=main.dump([]),
        source="test",
    )
    new = PatchCatalogEntry(
        patch_key="kb-new",
        patch_ref="KB-NEW",
        vendor="microsoft",
        product="windows",
        title="New cumulative update",
        severity="high",
        supersedes_json=main.dump(["KB-OLD"]),
        source="test",
    )
    db.add_all([old, new])
    db.flush()
    db.add(PatchApplicability(
        id="app-old",
        patch_key=old.patch_key,
        agent_id=agent.id,
        status="missing",
        evidence="agent_scan",
    ))
    db.commit()

    campaign = make_campaign(db, payload_extra={"packages": ["KB-OLD"], "target_agent_ids": [agent.id]})
    guard = main.campaign_patch_applicability_guard(db, campaign)

    assert guard["state"] == "blocked"
    assert guard["blocking"] is True
    assert guard["patches"][0]["state"] == "superseded"
    assert guard["patches"][0]["preferred_replacement"] == "KB-NEW"


def test_applicability_guard_blocks_when_all_targets_report_not_missing(db):
    agent = make_agent(db, "not-applicable-agent")
    entry = PatchCatalogEntry(
        patch_key="kb-na",
        patch_ref="KB-NA",
        vendor="microsoft",
        product="windows",
        title="Already installed update",
        severity="high",
        supersedes_json=main.dump([]),
        source="test",
    )
    db.add(entry)
    db.flush()
    db.add(PatchApplicability(
        id="app-na",
        patch_key=entry.patch_key,
        agent_id=agent.id,
        status="installed_inferred",
        evidence="agent_scan",
    ))
    db.commit()

    campaign = make_campaign(db, payload_extra={"packages": ["KB-NA"], "target_agent_ids": [agent.id]})
    guard = main.campaign_patch_applicability_guard(db, campaign)

    assert guard["state"] == "blocked"
    assert guard["patches"][0]["state"] == "not_applicable"
    assert guard["patches"][0]["missing_assets"] == 0
