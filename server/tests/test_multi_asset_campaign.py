import os
import sys
from pathlib import Path

import pytest


TEST_DB = Path(__file__).resolve().parent / "test-multi-asset-campaign.db"
TEST_DB.unlink(missing_ok=True)
SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "M" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"
os.environ["THREAT_INTEL_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app import main
from app.models import Agent, VulnerabilityFinding
from app.schemas import CampaignCreate


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


def agent(aid):
    return Agent(
        id=aid,
        hostname=f"{aid}.local",
        os_family="linux",
        os_name="Linux",
        token_hash=(aid.replace("-", "") + "m" * 64)[:64],
        tags="[]",
    )


def test_campaign_freezes_exact_multi_asset_snapshot(db):
    a1 = agent("multi-a1")
    a2 = agent("multi-a2")
    a3 = agent("multi-a3")
    db.add_all([a1, a2, a3])
    db.commit()

    created = main.create_campaign(
        CampaignCreate(
            name="Hub exact target",
            target_os="linux",
            ring_percent=100,
            action="install_updates",
            payload={"packages": ["KB-HUB"]},
            target_agent_ids=[a1.id, a2.id],
        ),
        principal={"actor": "user:operator", "role": "operator"},
        db=db,
    )
    campaign = db.get(main.Campaign, created["id"])

    candidates = main.campaign_candidates(db, campaign)

    assert {item.id for item in candidates} == {a1.id, a2.id}
    payload = main.load(campaign.payload_json, {})
    assert payload["target_agent_ids"] == [a1.id, a2.id]
    assert payload["target_agent_count"] == 2


def test_multi_asset_campaign_rejects_missing_target(db):
    a1 = agent("multi-existing")
    db.add(a1)
    db.commit()

    with pytest.raises(main.HTTPException) as exc:
        main.create_campaign(
            CampaignCreate(
                name="Missing target",
                action="install_updates",
                payload={"packages": ["KB-MISSING"]},
                target_agent_ids=[a1.id, "does-not-exist"],
            ),
            principal={"actor": "user:operator", "role": "operator"},
            db=db,
        )

    assert exc.value.status_code == 404


def test_single_source_finding_cannot_bind_multi_asset_campaign(db):
    a1 = agent("multi-finding-a1")
    a2 = agent("multi-finding-a2")
    finding = VulnerabilityFinding(
        id="multi-source-finding",
        source="openvas",
        external_id="multi-source",
        scan_id="scan",
        agent=a1,
        host=a1.hostname,
        cve="CVE-2026-42424",
        title="Multi source",
        severity="high",
        cvss=8.0,
        status="open",
    )
    db.add_all([a1, a2, finding])
    db.commit()

    with pytest.raises(main.HTTPException) as exc:
        main.create_campaign(
            CampaignCreate(
                name="Invalid evidence scope",
                action="install_updates",
                payload={"packages": ["KB-EVIDENCE"]},
                target_agent_ids=[a1.id, a2.id],
                target_finding_id=finding.id,
            ),
            principal={"actor": "user:operator", "role": "operator"},
            db=db,
        )

    assert exc.value.status_code == 400
    assert "single source finding" in str(exc.value.detail)
