import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

TEST_DB=Path(__file__).resolve().parent/"test-patch-feeds.db"
TEST_DB.unlink(missing_ok=True)
SERVER_ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SERVER_ROOT))
os.environ["DATABASE_URL"]=f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"]="F"*48
os.environ["BREAK_GLASS_ADMIN_TOKEN"]=""
os.environ["GREENBONE_ENABLED"]="false"
os.environ["THREAT_INTEL_ENABLED"]="false"

from app.database import Base, SessionLocal, engine
from app import main
from app.models import PatchCatalogEntry, PatchFeedProvider


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


def provider(**kwargs):
    values=dict(
        id="feed-1",name="curated-test",provider_type="curated",enabled=True,
        priority=700,ttl_hours=168,interval_seconds=3600,
        failure_threshold=2,cooldown_seconds=600,
        records_json=main.dump([{"patch_ref":"KB777","classification":"cumulative"}]),
        created_by="user:admin",updated_by="user:admin",
    )
    values.update(kwargs)
    return PatchFeedProvider(**values)


def test_due_respects_interval_and_circuit():
    p=provider()
    ref=datetime.now(timezone.utc)
    assert main.patch_feed_due(p,ref) is True
    p.last_attempt_at=ref
    assert main.patch_feed_due(p,ref+timedelta(seconds=100)) is False
    assert main.patch_feed_due(p,ref+timedelta(seconds=3601)) is True
    p.circuit_open_until=ref+timedelta(hours=1)
    assert main.patch_feed_due(p,ref+timedelta(seconds=1800)) is False
    assert main.patch_feed_due(p,ref+timedelta(seconds=3601)) is True


def test_curated_provider_sync_enriches_catalog(db):
    db.add(PatchCatalogEntry(patch_key="kb777",patch_ref="KB777",title="Observed",severity="unknown"))
    p=provider()
    db.add(p);db.commit()
    result=main.run_patch_feed_provider(db,p,"user:operator")
    db.refresh(p)
    entry=db.get(PatchCatalogEntry,"kb777")
    assert result["status"]=="ok"
    assert entry.classification=="cumulative"
    assert p.consecutive_failures==0
    assert p.last_success_at is not None


def test_failures_open_circuit(db):
    p=provider(provider_type="missing-adapter")
    db.add(p);db.commit()
    with pytest.raises(RuntimeError):
        main.run_patch_feed_provider(db,p)
    db.refresh(p)
    assert p.consecutive_failures==1
    assert p.circuit_open_until is None
    with pytest.raises(RuntimeError):
        main.run_patch_feed_provider(db,p)
    db.refresh(p)
    assert p.consecutive_failures==2
    assert p.circuit_open_until is not None
    result=main.run_patch_feed_provider(db,p)
    assert result["status"]=="circuit_open"


def test_report_exposes_health(db):
    p=provider()
    db.add(p);db.commit()
    report=main.patch_feed_orchestrator_report(db)
    assert report["summary"]["providers"]==1
    assert report["summary"]["enabled"]==1
    assert report["providers"][0]["name"]=="curated-test"
