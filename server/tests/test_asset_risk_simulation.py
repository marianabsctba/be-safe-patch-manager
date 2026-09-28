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
from app.models import Agent, VulnerabilityFinding
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


def make_agent():
    return Agent(
        id="sim-agent",
        hostname="sim-agent.local",
        os_family="linux",
        os_name="Linux",
        token_hash="s" * 64,
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
