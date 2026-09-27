import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest


TEST_DB = Path(__file__).resolve().parent / "test-threat-intel.db"
TEST_DB.unlink(missing_ok=True)
SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "T" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"
os.environ["THREAT_INTEL_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app import main, threat_intel
from app.models import VulnerabilityFinding


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


def add_finding(db, fid, cve, raw=None):
    item = VulnerabilityFinding(
        id=fid,
        source="openvas",
        external_id=f"external-{fid}",
        scan_id="scan",
        host=f"{fid}.local",
        cve=cve,
        title=f"Finding {fid}",
        severity="critical",
        cvss=9.8,
        status="open",
        raw_json=json.dumps(raw or {}),
        first_seen=datetime(2026, 9, 1, tzinfo=timezone.utc),
        last_seen=datetime(2026, 9, 27, tzinfo=timezone.utc),
    )
    db.add(item)
    db.commit()
    return item


def test_epss_parser_batches_and_normalizes(monkeypatch):
    calls = []

    def fake_get(url, timeout):
        calls.append((url, timeout))
        return {
            "data": [
                {
                    "cve": "CVE-2026-12345",
                    "epss": "0.75",
                    "percentile": "0.98",
                    "date": "2026-09-27",
                }
            ]
        }

    monkeypatch.setattr(threat_intel, "_get_json", fake_get)
    result = threat_intel.fetch_epss(["cve-2026-12345"])

    assert result["CVE-2026-12345"]["epss"] == 0.75
    assert result["CVE-2026-12345"]["epss_percentile"] == 0.98
    assert "cve=CVE-2026-12345" in calls[0][0]


def test_kev_parser_extracts_operational_fields(monkeypatch):
    monkeypatch.setattr(
        threat_intel,
        "_get_json",
        lambda url, timeout: {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-9999",
                    "dateAdded": "2026-09-20",
                    "dueDate": "2026-10-01",
                    "vendorProject": "Example",
                    "product": "Widget",
                    "requiredAction": "Apply mitigations",
                    "knownRansomwareCampaignUse": "Known",
                }
            ]
        },
    )

    result = threat_intel.fetch_kev()

    assert result["CVE-2026-9999"]["kev"] is True
    assert result["CVE-2026-9999"]["kev_due_date"] == "2026-10-01"
    assert result["CVE-2026-9999"]["kev_ransomware_use"] == "Known"


def test_sync_enriches_findings_and_preserves_scanner_raw(db, monkeypatch):
    item = add_finding(db, "intel-1", "CVE-2026-12345", {"greenbone_task_id": "task-1"})

    monkeypatch.setattr(
        main,
        "get_threat_intel_config",
        lambda: threat_intel.ThreatIntelConfig(
            enabled=True,
            interval_seconds=21600,
            timeout_seconds=20,
            epss_url="https://epss.invalid",
            kev_url="https://kev.invalid",
        ),
    )
    monkeypatch.setattr(
        main,
        "fetch_epss",
        lambda cves, config: {
            "CVE-2026-12345": {
                "epss": 0.91,
                "epss_percentile": 0.99,
                "epss_date": "2026-09-27",
            }
        },
    )
    monkeypatch.setattr(
        main,
        "fetch_kev",
        lambda config: {
            "CVE-2026-12345": {
                "kev": True,
                "kev_date_added": "2026-09-20",
                "kev_due_date": "2026-10-01",
            }
        },
    )

    details = main.run_threat_intel_sync()
    db.refresh(item)
    raw = json.loads(item.raw_json)

    assert details["epss_enriched"] == 1
    assert details["kev_enriched"] == 1
    assert raw["greenbone_task_id"] == "task-1"
    assert raw["threat_intel"]["epss"] == 0.91
    assert raw["threat_intel"]["kev"] is True
    assert main.vulnerability_risk(item)["level"] == "urgent"


def test_partial_source_failure_is_degraded_not_destructive(db, monkeypatch):
    item = add_finding(
        db,
        "intel-2",
        "CVE-2026-54321",
        {"threat_intel": {"epss": 0.42, "kev": False}},
    )

    monkeypatch.setattr(
        main,
        "get_threat_intel_config",
        lambda: threat_intel.ThreatIntelConfig(
            enabled=True,
            interval_seconds=21600,
            timeout_seconds=20,
            epss_url="https://epss.invalid",
            kev_url="https://kev.invalid",
        ),
    )

    def epss_failure(cves, config):
        raise RuntimeError("FIRST unavailable")

    monkeypatch.setattr(main, "fetch_epss", epss_failure)
    monkeypatch.setattr(main, "fetch_kev", lambda config: {})

    details = main.run_threat_intel_sync()
    db.refresh(item)
    raw = json.loads(item.raw_json)

    assert "epss" in details["source_errors"]
    assert raw["threat_intel"]["epss"] == 0.42
    assert raw["threat_intel"]["kev"] is False

    state = main.integration_state(db, "threat_intel")
    assert state.status == "degraded"


def test_scanner_upsert_preserves_existing_threat_intel(db):
    item = add_finding(
        db,
        "intel-3",
        "CVE-2026-77777",
        {"threat_intel": {"epss": 0.88, "kev": True}},
    )
    item.external_id = "scanner-id"
    db.commit()

    main.upsert_vulnerability_findings(
        db,
        "openvas",
        "scan-2",
        [{
            "external_id": "scanner-id",
            "host": "intel-3.local",
            "cves": ["CVE-2026-77777"],
            "title": "Updated scanner finding",
            "severity": "critical",
            "cvss": 9.8,
            "raw": {"greenbone_task_id": "task-new"},
        }],
    )

    db.refresh(item)
    raw = json.loads(item.raw_json)
    assert raw["greenbone_task_id"] == "task-new"
    assert raw["threat_intel"]["epss"] == 0.88
    assert raw["threat_intel"]["kev"] is True
