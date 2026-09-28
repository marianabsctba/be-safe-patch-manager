import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

TEST_DB = Path(__file__).resolve().parent / "test-patch-metadata.db"
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
from app.models import PatchCatalogEntry, PatchMetadataEvidence
from app.schemas import PatchMetadataImportRequest, PatchMetadataRecord


@pytest.fixture(autouse=True)
def clean_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db():
    s=SessionLocal()
    try: yield s
    finally: s.close()


def add_patch(db):
    e=PatchCatalogEntry(patch_key="kb999",patch_ref="KB999",title="Observed title",severity="unknown")
    db.add(e);db.commit();return e


def test_higher_priority_source_wins_and_lower_conflict_is_kept(db):
    e=add_patch(db)
    high=PatchMetadataImportRequest(
        source="vendor",priority=800,ttl_hours=168,
        records=[PatchMetadataRecord(patch_ref="KB999",title="Vendor title",classification="cumulative")]
    )
    main.import_patch_metadata(db,high,"user:operator")
    low=PatchMetadataImportRequest(
        source="community",priority=100,ttl_hours=168,
        records=[PatchMetadataRecord(patch_ref="KB999",title="Community title")]
    )
    result=main.import_patch_metadata(db,low,"user:operator")
    db.refresh(e)
    assert e.title=="Vendor title"
    assert result["summary"]["rejected_conflicts"]==1
    state=main.patch_enrichment_state(e)
    assert state["fields"]["title"]["source"]=="vendor"
    assert state["conflicts"][-1]["incoming_source"]=="community"


def test_dry_run_does_not_mutate_or_store_evidence(db):
    e=add_patch(db)
    body=PatchMetadataImportRequest(
        source="vendor",priority=800,dry_run=True,
        records=[PatchMetadataRecord(patch_ref="KB999",product="Windows 11")]
    )
    result=main.import_patch_metadata(db,body,"user:operator")
    db.refresh(e)
    assert e.product==""
    assert result["summary"]["changed_fields"]==1
    assert db.query(PatchMetadataEvidence).count()==0


def test_stale_metadata_is_reported(db):
    e=add_patch(db)
    observed=datetime.now(timezone.utc)-timedelta(hours=10)
    body=PatchMetadataImportRequest(
        source="vendor",priority=800,observed_at=observed,ttl_hours=1,
        records=[PatchMetadataRecord(patch_ref="KB999",classification="security")]
    )
    main.import_patch_metadata(db,body,"user:operator")
    db.refresh(e)
    state=main.patch_enrichment_state(e, datetime.now(timezone.utc))
    assert state["stale"] is True
    assert "classification" in state["stale_fields"]


def test_enriched_cves_are_merged_into_catalog_report(db):
    add_patch(db)
    body=PatchMetadataImportRequest(
        source="vendor",priority=800,
        records=[PatchMetadataRecord(patch_ref="KB999",cves=["CVE-2026-12345"])]
    )
    main.import_patch_metadata(db,body,"user:operator")
    report=main.patch_catalog_report(db)
    assert report["items"][0]["threat"]["cves"]==["CVE-2026-12345"]
