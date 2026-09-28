import os
import sys
from pathlib import Path

import pytest


TEST_DB = Path(__file__).resolve().parent / "test-patch-catalog.db"
TEST_DB.unlink(missing_ok=True)
SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "C" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"
os.environ["THREAT_INTEL_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app import main
from app.models import Agent, Campaign, PatchJob, PatchBlockRule


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
        id="catalog-agent",
        hostname="catalog.local",
        os_family="windows",
        os_name="Windows 11",
        token_hash="c" * 64,
        tags="[]",
    )


def test_scan_populates_catalog_and_missing_state(db):
    agent = make_agent()
    db.add(agent)
    db.commit()

    result = main.sync_patch_catalog_for_agent(db, agent, [{
        "id": "wu-1",
        "title": "Security Update",
        "kb": ["KB5039999"],
        "severity": "Critical",
        "reboot_behavior": "CanRequestReboot",
    }])
    db.commit()

    report = main.patch_catalog_report(db)
    item = report["items"][0]
    assert result["catalog_created"] == 1
    assert item["patch_ref"] == "KB5039999"
    assert item["states"]["missing"] == 1
    assert item["states"]["installed_inferred"] == 0


def test_successful_targeted_job_allows_installed_inference(db):
    agent = make_agent()
    db.add(agent)
    db.commit()
    main.sync_patch_catalog_for_agent(db, agent, [{
        "id": "wu-1",
        "title": "Security Update",
        "kb": ["KB5039999"],
        "severity": "Critical",
    }])
    campaign = Campaign(
        id="catalog-campaign",
        name="Install KB",
        target_os="windows",
        ring_percent=100,
        action="install_updates",
        status="deployed",
        payload_json=main.dump({"packages": ["KB5039999"]}),
    )
    job = PatchJob(
        id="catalog-job",
        campaign=campaign,
        agent=agent,
        action="install_updates",
        status="success",
        payload_json=main.dump({"packages": ["KB5039999"]}),
    )
    db.add_all([campaign, job])
    db.commit()

    main.sync_patch_catalog_for_agent(db, agent, [])
    db.commit()

    item = main.patch_catalog_report(db)["items"][0]
    assert item["states"]["missing"] == 0
    assert item["states"]["installed_inferred"] == 1


def test_patch_guard_makes_catalog_readiness_blocked(db):
    agent = make_agent()
    db.add(agent)
    db.commit()
    main.sync_patch_catalog_for_agent(db, agent, [{
        "id": "wu-1",
        "title": "Security Update",
        "kb": ["KB5039999"],
        "severity": "Critical",
    }])
    db.add(PatchBlockRule(
        id="catalog-rule",
        name="Catalog guard",
        patch_ref="KB5039999",
        target_os="all",
        target_tag="",
        reason="Known regression",
        enabled=True,
        created_by="user:admin",
        updated_by="user:admin",
    ))
    db.commit()

    item = main.patch_catalog_report(db)["items"][0]
    assert item["guard"]["blocked"] is True
    assert item["deployment_readiness"]["status"] == "blocked"
