import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


TEST_DB = Path(__file__).resolve().parent / "test-remediation-queue.db"
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
from app.models import Agent, VulnerabilityFinding, VulnerabilitySlaException


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


def make_agent(aid="agent-1", tags=None):
    return Agent(
        id=aid,
        hostname=f"{aid}.local",
        os_family="linux",
        os_name="Linux",
        token_hash=(aid.replace("-", "") + "x" * 64)[:64],
        tags=main.dump(tags or []),
    )


def make_finding(fid, *, agent=None, cvss=9.8, age_hours=96, patch_refs=None, raw=None):
    seen = REFERENCE - timedelta(hours=age_hours)
    return VulnerabilityFinding(
        id=fid,
        source="openvas",
        external_id=f"ext-{fid}",
        scan_id="scan",
        agent=agent,
        host=f"{fid}.local",
        cve=f"CVE-2026-{10000 + len(fid)}",
        title=f"Finding {fid}",
        severity="critical" if cvss >= 9 else "high",
        cvss=cvss,
        patch_refs_json=main.dump(patch_refs or []),
        raw_json=main.dump(raw or {}),
        status="open",
        first_seen=seen,
        last_seen=seen,
    )


def test_queue_prioritizes_kev_breached_patchable_finding(db):
    agent = make_agent(tags=["prod", "internet-facing"])
    urgent = make_finding(
        "urgent",
        agent=agent,
        patch_refs=["KB5039999"],
        raw={"threat_intel": {"epss": 0.95, "kev": True}},
    )
    db.add_all([agent, urgent])
    db.commit()

    report = main.remediation_queue_report(db, REFERENCE)
    item = report["items"][0]
    rec = item["recommendation"]

    assert rec["action"] == "patch_now"
    assert rec["eligible_for_campaign"] is True
    assert rec["priority_score"] == 100
    assert "CVE presente no CISA KEV" in rec["reasons"]
    assert report["summary"]["patch_now"] == 1


def test_unmatched_finding_requires_asset_correlation(db):
    item = make_finding("unmatched", patch_refs=["pkg-1"])
    db.add(item)
    db.commit()

    rec = main.remediation_recommendation(item, REFERENCE)

    assert rec["action"] == "correlate_asset"
    assert rec["eligible_for_campaign"] is False
    assert any("sem endpoint" in reason for reason in rec["reasons"])


def test_active_sla_exception_suppresses_campaign_recommendation(db):
    agent = make_agent()
    item = make_finding("excepted", agent=agent, patch_refs=["pkg-1"])
    exception = VulnerabilitySlaException(
        id="exception-1",
        finding=item,
        reason="Janela de mudança aprovada",
        approved_by="user:admin",
        expires_at=REFERENCE + timedelta(days=2),
        created_at=REFERENCE,
    )
    db.add_all([agent, item, exception])
    db.commit()

    rec = main.remediation_recommendation(item, REFERENCE)

    assert rec["action"] == "exception_active"
    assert rec["eligible_for_campaign"] is False


def test_matched_finding_without_patch_reference_recommends_triage(db):
    agent = make_agent()
    item = make_finding("triage", agent=agent, patch_refs=[])
    db.add_all([agent, item])
    db.commit()

    rec = main.remediation_recommendation(item, REFERENCE)

    assert rec["action"] == "scan_or_manual_triage"
    assert rec["eligible_for_campaign"] is True
    assert rec["patchable"] is False



def test_vulnerability_list_applies_limit_after_risk_sort(db):
    agent = make_agent()
    older_urgent = make_finding(
        "older-urgent",
        agent=agent,
        cvss=9.8,
        age_hours=240,
        raw={"threat_intel": {"epss": 0.95, "kev": True}},
    )
    newer_lower = make_finding(
        "newer-lower",
        agent=agent,
        cvss=7.0,
        age_hours=1,
        raw={"threat_intel": {"epss": 0.01, "kev": False}},
    )
    db.add_all([agent, older_urgent, newer_lower])
    db.commit()

    items = main.list_vulnerabilities(
        limit=1,
        _={"actor": "viewer"},
        db=db,
    )

    assert len(items) == 1
    assert items[0]["id"] == older_urgent.id
