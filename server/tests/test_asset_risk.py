import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


TEST_DB = Path(__file__).resolve().parent / "test-asset-risk.db"
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
from app.models import Agent, AssetRiskSnapshot, VulnerabilityFinding


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


def make_agent(aid, tags):
    return Agent(
        id=aid,
        hostname=f"{aid}.local",
        os_family="linux",
        os_name="Linux",
        ip_address="10.0.0.10",
        token_hash=(aid.replace("-", "") + "x" * 64)[:64],
        tags=main.dump(tags),
    )


def make_finding(fid, agent, severity, cvss, raw=None):
    seen = REFERENCE - timedelta(days=30)
    return VulnerabilityFinding(
        id=fid,
        source="openvas",
        external_id=f"ext-{fid}",
        scan_id="scan",
        agent=agent,
        host=agent.hostname,
        cve=f"CVE-2026-{1000 + len(fid)}",
        title=f"Finding {fid}",
        severity=severity,
        cvss=cvss,
        raw_json=main.dump(raw or {}),
        status="open",
        first_seen=seen,
        last_seen=REFERENCE,
    )


def test_asset_criticality_uses_highest_tag_score():
    agent = make_agent("asset-1", ["dev", "prod", "tier0"])

    result = main.asset_criticality(agent)

    assert result["score"] == 5
    assert result["source"] == "tags"
    assert result["contributors"][0]["tag"] == "tier0"


def test_external_asset_gets_exposure_multiplier():
    agent = make_agent("asset-2", ["prod", "internet-facing"])

    exposure = main.asset_exposure(agent)

    assert exposure["external"] is True
    assert exposure["multiplier"] == 1.2


def test_compensating_controls_reduce_asset_risk():
    base = make_agent("base", ["prod", "internet-facing"])
    protected = make_agent("protected", ["prod", "internet-facing", "segmented", "edr-protected"])
    f1 = make_finding(
        "f-base",
        base,
        "critical",
        9.8,
        {"threat_intel": {"epss": 0.9, "kev": True}},
    )
    f2 = make_finding(
        "f-protected",
        protected,
        "critical",
        9.8,
        {"threat_intel": {"epss": 0.9, "kev": True}},
    )

    base_risk = main.asset_risk_score(base, [f1], REFERENCE)
    protected_risk = main.asset_risk_score(protected, [f2], REFERENCE)

    assert protected_risk["compensating"]["multiplier"] < 1.0
    assert protected_risk["score"] < base_risk["score"]


def test_asset_risk_report_orders_highest_risk_first(db):
    critical = make_agent("critical-asset", ["tier0", "internet-facing"])
    low = make_agent("low-asset", ["lab"])
    db.add_all([
        critical,
        low,
        make_finding(
            "critical-f",
            critical,
            "critical",
            9.8,
            {"threat_intel": {"epss": 0.95, "kev": True, "kev_ransomware_use": "Known"}},
        ),
        make_finding("low-f", low, "medium", 5.0, {}),
    ])
    db.commit()

    report = main.asset_risk_report(db, REFERENCE)

    assert report["model"] == "be_safe_asset_risk_v1"
    assert report["scale"] == {"min": 0, "max": 1000}
    assert report["assets"][0]["agent_id"] == "critical-asset"
    assert report["assets"][0]["risk"]["score"] > report["assets"][1]["risk"]["score"]


def test_detection_risk_is_explainable():
    agent = make_agent("asset-3", ["prod"])
    item = make_finding(
        "f-risk",
        agent,
        "critical",
        9.8,
        {"threat_intel": {"epss": 0.8, "kev": True, "kev_ransomware_use": "Known"}},
    )

    result = main.finding_detection_risk(item, REFERENCE)
    factors = {factor["factor"] for factor in result["factors"]}

    assert result["score"] <= 100
    assert {"cvss", "epss", "known_exploited", "ransomware", "age"}.issubset(factors)



def test_asset_risk_report_applies_configured_risk_appetite(db, monkeypatch):
    monkeypatch.setattr(main, "ASSET_RISK_APPETITE", 700)
    agent = make_agent("appetite-asset", ["tier0", "internet-facing"])
    db.add_all([
        agent,
        make_finding(
            "appetite-f",
            agent,
            "critical",
            9.8,
            {"threat_intel": {"epss": 0.95, "kev": True, "kev_ransomware_use": "Known"}},
        ),
    ])
    db.commit()

    report = main.asset_risk_report(db, REFERENCE)

    assert report["summary"]["risk_appetite"] == 700
    assert report["summary"]["above_risk_appetite"] == 1



def test_asset_risk_snapshot_persists_and_history_returns_latest(db):
    agent = make_agent("history-asset", ["prod"])
    finding = make_finding("history-f", agent, "high", 8.0, {})
    db.add_all([agent, finding])
    db.commit()

    result = main.capture_asset_risk_snapshots(
        db,
        source="test",
        reference=REFERENCE,
        minimum_interval_seconds=0,
    )
    history = main.asset_risk_history(db, agent_id=agent.id)

    assert result["created"] == 1
    assert history["items"][0]["agent_id"] == agent.id
    assert history["items"][0]["source"] == "test"
    assert history["items"][0]["score"] >= 0


def test_asset_risk_trend_detects_deterioration(db):
    agent = make_agent("trend-asset", ["prod"])
    finding = make_finding("trend-f", agent, "medium", 5.0, {})
    db.add_all([agent, finding])
    db.commit()

    baseline = main.asset_risk_score(agent, [finding], REFERENCE)
    db.add(AssetRiskSnapshot(
        agent_id=agent.id,
        score=baseline["score"],
        level=baseline["level"],
        criticality=baseline["asset_criticality"]["score"],
        external=baseline["exposure"]["external"],
        open_findings=baseline["open_findings"],
        factors_json=main.dump(baseline["top_factors"]),
        source="baseline",
        captured_at=REFERENCE - timedelta(days=1),
    ))
    finding.cvss = 9.8
    finding.severity = "critical"
    finding.raw_json = main.dump({"threat_intel": {"epss": 0.95, "kev": True}})
    db.commit()

    report = main.asset_risk_report(db, REFERENCE)
    trend = report["assets"][0]["risk"]["trend"]

    assert trend["direction"] == "up"
    assert trend["delta"] > 0
    assert trend["previous_score"] == baseline["score"]


def test_snapshot_respects_minimum_interval(db):
    agent = make_agent("interval-asset", ["prod"])
    finding = make_finding("interval-f", agent, "high", 8.0, {})
    db.add_all([agent, finding])
    db.commit()

    first = main.capture_asset_risk_snapshots(
        db,
        source="first",
        reference=REFERENCE,
        minimum_interval_seconds=3600,
    )
    second = main.capture_asset_risk_snapshots(
        db,
        source="second",
        reference=REFERENCE + timedelta(minutes=10),
        minimum_interval_seconds=3600,
    )

    assert first["created"] == 1
    assert second["created"] == 0
    assert second["skipped"] == 1



def test_asset_risk_decomposition_is_explainable():
    agent = make_agent("decomp-asset", ["tier0", "internet-facing", "segmented"])
    finding = make_finding(
        "decomp-f",
        agent,
        "critical",
        9.8,
        {"threat_intel": {"epss": 0.9, "kev": True}},
    )

    risk = main.asset_risk_score(agent, [finding], REFERENCE)
    names = {item["name"] for item in risk["decomposition"]}

    assert "findings:critical" in names
    assert "asset_criticality" in names
    assert "external_exposure" in names
    assert "compensating_controls" in names
    assert any(item["raw"] < 0 for item in risk["decomposition"] if item["name"] == "compensating_controls")


def test_asset_risk_report_aggregates_top_contributors(db):
    agent = make_agent("contrib-asset", ["tier0", "internet-facing"])
    db.add_all([
        agent,
        make_finding(
            "contrib-f",
            agent,
            "critical",
            9.8,
            {"threat_intel": {"epss": 0.95, "kev": True}},
        ),
    ])
    db.commit()

    report = main.asset_risk_report(db, REFERENCE)

    assert report["top_contributors"]
    assert report["top_contributors"][0]["raw"] > 0
