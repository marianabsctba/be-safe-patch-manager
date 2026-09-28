import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest


TEST_DB = Path(__file__).resolve().parent / "test-risk-simulation.db"
TEST_DB.unlink(missing_ok=True)
SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "S" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"
os.environ["THREAT_INTEL_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app import main
from app.models import Agent, Campaign, PatchJob, VulnerabilityFinding
from app.schemas import AssetRiskSimulationRequest


REFERENCE = datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc)


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


def make_agent(aid="sim-agent"):
    token_seed = (aid.replace("-", "") + "s" * 64)[:64]
    return Agent(
        id=aid,
        hostname=f"{aid}.local",
        os_family="linux",
        os_name="Linux",
        token_hash=token_seed,
        tags=main.dump(["tier0", "internet-facing"]),
    )


def make_finding(fid, severity, cvss, epss=0.0, kev=False):
    return VulnerabilityFinding(
        id=fid,
        source="openvas",
        external_id=fid,
        scan_id="scan-1",
        host="sim-agent.local",
        ip_address="10.0.0.10",
        cve=f"CVE-2026-{fid[-4:].zfill(4)}",
        title=f"Finding {fid}",
        severity=severity,
        cvss=cvss,
        port="443",
        solution="Patch",
        patch_refs_json="[]",
        status="open",
        raw_json=main.dump({"threat_intel": {"epss": epss, "kev": kev}}),
        first_seen=REFERENCE,
        last_seen=REFERENCE,
    )


def test_simulation_reduces_score_without_mutating_findings(db, monkeypatch):
    agent = make_agent()
    f1 = make_finding("finding-0001", "critical", 9.8, 0.95, True)
    f2 = make_finding("finding-0002", "high", 8.0, 0.4, False)
    f1.agent = agent
    f2.agent = agent
    db.add_all([agent, f1, f2])
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)

    result = main.simulate_asset_risk_reduction(
        agent.id,
        AssetRiskSimulationRequest(finding_ids=[f1.id]),
        _={"actor": "viewer"},
        db=db,
    )

    db.refresh(f1)
    db.refresh(f2)

    assert result["mode"] == "simulation_only"
    assert result["before"]["score"] >= result["after"]["score"]
    assert result["impact"]["delta"] >= 0
    assert result["impact"]["reduction_percent"] >= 0
    assert f1.status == "open"
    assert f2.status == "open"


def test_simulation_rejects_finding_from_other_asset(db, monkeypatch):
    agent = make_agent()
    other = Agent(
        id="other-agent",
        hostname="other.local",
        os_family="linux",
        os_name="Linux",
        token_hash="o" * 64,
        tags="[]",
    )
    f1 = make_finding("finding-0001", "critical", 9.8, 0.95, True)
    f1.agent = other
    db.add_all([agent, other, f1])
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)

    with pytest.raises(main.HTTPException) as exc:
        main.simulate_asset_risk_reduction(
            agent.id,
            AssetRiskSimulationRequest(finding_ids=[f1.id]),
            _={"actor": "viewer"},
            db=db,
        )

    assert exc.value.status_code == 400


def test_simulation_deduplicates_requested_ids(db, monkeypatch):
    agent = make_agent()
    f1 = make_finding("finding-0001", "critical", 9.8, 0.95, True)
    f1.agent = agent
    db.add_all([agent, f1])
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)

    result = main.simulate_asset_risk_reduction(
        agent.id,
        AssetRiskSimulationRequest(finding_ids=[f1.id, f1.id]),
        _={"actor": "viewer"},
        db=db,
    )

    assert result["excluded_findings"] == [f1.id]



def test_opportunity_report_ranks_larger_reduction_first(db, monkeypatch):
    agent = make_agent()
    critical = make_finding("finding-crit", "critical", 9.8, 0.95, True)
    medium = make_finding("finding-med", "medium", 5.0, 0.05, False)
    critical.agent = agent
    medium.agent = agent
    db.add_all([agent, critical, medium])
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)

    report = main.risk_reduction_opportunities_report(db, REFERENCE)

    assert report["mode"] == "simulation_only"
    assert len(report["items"]) == 2
    assert report["items"][0]["risk_reduction"] >= report["items"][1]["risk_reduction"]
    assert report["items"][0]["finding_id"] == critical.id


def test_opportunity_report_is_read_only(db, monkeypatch):
    agent = make_agent()
    finding = make_finding("finding-readonly", "critical", 9.8, 0.95, True)
    finding.agent = agent
    db.add_all([agent, finding])
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)

    before_status = finding.status
    report = main.risk_reduction_opportunities_report(db, REFERENCE)
    db.refresh(finding)

    assert report["items"]
    assert finding.status == before_status == "open"



def test_risk_reduction_plan_recalculates_marginal_steps(db, monkeypatch):
    agent = make_agent()
    critical = make_finding("plan-critical", "critical", 9.8, 0.95, True)
    high = make_finding("plan-high", "high", 8.5, 0.6, False)
    medium = make_finding("plan-medium", "medium", 5.0, 0.1, False)
    for finding in (critical, high, medium):
        finding.agent = agent
    db.add_all([agent, critical, high, medium])
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)
    monkeypatch.setattr(main, "ASSET_RISK_APPETITE", 1)

    report = main.risk_reduction_plan_report(
        db,
        agent_id=agent.id,
        reference=REFERENCE,
        max_steps=3,
    )

    assert report["mode"] == "simulation_only"
    assert report["steps"]
    assert report["steps"][0]["marginal_reduction"] >= 0
    assert report["steps"][0]["before_score"] == report["initial_score"]
    for index in range(1, len(report["steps"])):
        assert report["steps"][index]["before_score"] == report["steps"][index - 1]["after_score"]


def test_risk_reduction_plan_stops_when_appetite_reached(db, monkeypatch):
    agent = make_agent()
    finding = make_finding("plan-one", "critical", 9.8, 0.95, True)
    finding.agent = agent
    db.add_all([agent, finding])
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)
    monkeypatch.setattr(main, "ASSET_RISK_APPETITE", 700)

    report = main.risk_reduction_plan_report(
        db,
        agent_id=agent.id,
        reference=REFERENCE,
        max_steps=10,
    )

    if report["initial_score"] < report["risk_appetite"]:
        assert report["steps"] == []
        assert report["target_reached"] is True
    else:
        assert len(report["steps"]) <= 1
        assert report["projected_score"] <= report["initial_score"]


def test_risk_reduction_plan_is_read_only(db, monkeypatch):
    agent = make_agent()
    finding = make_finding("plan-readonly", "high", 8.0, 0.4, False)
    finding.agent = agent
    db.add_all([agent, finding])
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)
    monkeypatch.setattr(main, "ASSET_RISK_APPETITE", 1)

    main.risk_reduction_plan_report(
        db,
        agent_id=agent.id,
        reference=REFERENCE,
        max_steps=5,
    )
    db.refresh(finding)

    assert finding.status == "open"



def test_risk_reduction_plan_exposes_campaign_eligibility(db, monkeypatch):
    agent = make_agent()
    finding = make_finding("plan-campaign", "critical", 9.8, 0.95, True)
    finding.agent = agent
    finding.patch_refs_json = main.dump(["KB5039999"])
    db.add_all([agent, finding])
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)
    monkeypatch.setattr(main, "ASSET_RISK_APPETITE", 1)

    report = main.risk_reduction_plan_report(
        db,
        agent_id=agent.id,
        reference=REFERENCE,
        max_steps=1,
    )

    assert report["steps"]
    step = report["steps"][0]
    assert step["finding_id"] == finding.id
    assert "eligible_for_campaign" in step
    assert step["patch_refs"] == ["KB5039999"]



def test_remediation_hub_groups_findings_by_patch_reference(db, monkeypatch):
    a1 = make_agent("hub-a1")
    a2 = make_agent("hub-a2")
    f1 = make_finding("hub-f1", "critical", 9.8, 0.95, True)
    f2 = make_finding("hub-f2", "high", 8.0, 0.6, False)
    f1.agent = a1
    f2.agent = a2
    f1.patch_refs_json = main.dump(["KB-HUB-001"])
    f2.patch_refs_json = main.dump(["KB-HUB-001"])
    db.add_all([a1, a2, f1, f2])
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)

    report = main.remediation_hub_report(db, REFERENCE)

    assert report["mode"] == "simulation_only"
    assert report["summary"]["remediation_groups"] == 1
    item = report["items"][0]
    assert item["patch_ref"] == "KB-HUB-001"
    assert item["finding_count"] == 2
    assert item["asset_count"] == 2
    assert item["risk_reduction"] >= 0
    assert len(item["affected_assets"]) == 2


def test_remediation_hub_recalculates_group_impact_per_asset(db, monkeypatch):
    agent = make_agent("hub-one")
    f1 = make_finding("hub-one-f1", "critical", 9.8, 0.95, True)
    f2 = make_finding("hub-one-f2", "high", 8.0, 0.6, False)
    f3 = make_finding("hub-one-other", "medium", 5.0, 0.1, False)
    for finding in (f1, f2, f3):
        finding.agent = agent
    f1.patch_refs_json = main.dump(["PKG-SECURITY"])
    f2.patch_refs_json = main.dump(["PKG-SECURITY"])
    f3.patch_refs_json = main.dump(["OTHER"])
    db.add_all([agent, f1, f2, f3])
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)

    report = main.remediation_hub_report(db, REFERENCE)
    item = next(row for row in report["items"] if row["patch_ref"] == "PKG-SECURITY")

    assert item["finding_count"] == 2
    assert item["asset_count"] == 1
    assert item["single_asset_campaign_ready"] is True
    asset = item["affected_assets"][0]
    assert asset["projected_score"] <= asset["before_score"]


def test_remediation_hub_is_read_only(db, monkeypatch):
    agent = make_agent("hub-readonly")
    finding = make_finding("hub-readonly-f", "critical", 9.8, 0.95, True)
    finding.agent = agent
    finding.patch_refs_json = main.dump(["KB-READONLY"])
    db.add_all([agent, finding])
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)

    main.remediation_hub_report(db, REFERENCE)
    db.refresh(finding)

    assert finding.status == "open"



def test_active_threat_watch_groups_kev_and_high_epss(db, monkeypatch):
    agent = make_agent()
    kev = make_finding("watch-0001", "critical", 9.8, 0.95, True)
    epss = make_finding("watch-0002", "high", 8.0, 0.80, False)
    quiet = make_finding("watch-0003", "medium", 5.0, 0.10, False)
    for finding in (kev, epss, quiet):
        finding.agent = agent
    kev.patch_refs_json = main.dump(["KB-WATCH"])
    db.add_all([agent, kev, epss, quiet])
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)

    report = main.active_threat_watch_report(db, REFERENCE)

    cves = {item["cve"] for item in report["items"]}
    assert kev.cve in cves
    assert epss.cve in cves
    assert quiet.cve not in cves
    kev_item = next(item for item in report["items"] if item["cve"] == kev.cve)
    assert kev_item["kev"] is True
    assert kev_item["asset_count"] == 1
    assert "KB-WATCH" in kev_item["patch_refs"]


def test_patch_confidence_uses_local_completed_job_history(db, monkeypatch):
    agent = make_agent()
    campaign = Campaign(
        id="confidence-campaign",
        name="Confidence",
        target_os="linux",
        action="install_updates",
        payload_json=main.dump({"packages": ["pkg-sec"]}),
        status="deployed",
    )
    jobs = []
    for index in range(10):
        jobs.append(PatchJob(
            id=f"confidence-job-{index}",
            campaign=campaign,
            agent=agent,
            action="install_updates",
            payload_json=campaign.payload_json,
            status="success" if index < 9 else "failed",
            finished_at=REFERENCE,
        ))
    db.add_all([agent, campaign, *jobs])
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)

    report = main.patch_confidence_report(db)
    item = next(row for row in report["items"] if row["patch_ref"] == "pkg-sec")

    assert item["completed_jobs"] == 10
    assert item["success"] == 9
    assert item["failed"] == 1
    assert item["success_rate"] == 90.0
    assert item["confidence"] == "medium"


def test_remediation_hub_includes_patch_confidence(db, monkeypatch):
    agent = make_agent()
    finding = make_finding("hub-confidence", "critical", 9.8, 0.95, True)
    finding.agent = agent
    finding.patch_refs_json = main.dump(["pkg-hub"])
    campaign = Campaign(
        id="hub-confidence-campaign",
        name="Hub confidence",
        target_os="linux",
        action="install_updates",
        payload_json=main.dump({"packages": ["pkg-hub"]}),
        status="deployed",
    )
    jobs = [
        PatchJob(
            id=f"hub-confidence-job-{index}",
            campaign=campaign,
            agent=agent,
            action="install_updates",
            payload_json=campaign.payload_json,
            status="success",
            finished_at=REFERENCE,
        )
        for index in range(5)
    ]
    db.add_all([agent, finding, campaign, *jobs])
    db.commit()
    monkeypatch.setattr(main, "now", lambda: REFERENCE)

    report = main.remediation_hub_report(db, REFERENCE)
    item = next(row for row in report["items"] if row["patch_ref"] == "pkg-hub")

    assert item["patch_confidence"] is not None
    assert item["patch_confidence"]["success_rate"] == 100.0
