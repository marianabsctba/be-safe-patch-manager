import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest


TEST_DB = Path(__file__).resolve().parent / "test-patch-lifecycle.db"
TEST_DB.unlink(missing_ok=True)
SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "L" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""
os.environ["GREENBONE_ENABLED"] = "false"
os.environ["THREAT_INTEL_ENABLED"] = "false"

from app.database import Base, SessionLocal, engine
from app import main
from app.models import PatchCatalogEntry
from app.schemas import PatchCatalogLifecycleUpdate


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


def entry(ref, release=None, supersedes=None, eol=None):
    return PatchCatalogEntry(
        patch_key=ref.lower(),
        patch_ref=ref,
        vendor="Microsoft",
        product="Windows",
        title=ref,
        severity="critical",
        release_date=release,
        eol_date=eol,
        supersedes_json=main.dump(supersedes or []),
    )


def test_second_tuesday_detection():
    patch = entry("KB1", datetime(2026, 9, 8, tzinfo=timezone.utc))
    intel = main.patch_release_intelligence(patch, datetime(2026, 9, 28, tzinfo=timezone.utc))
    assert intel["patch_tuesday"] is True
    assert intel["release_age_days"] == 20


def test_supersedence_graph_and_leaf_selection():
    old = entry("KB100")
    middle = entry("KB200", datetime(2026, 8, 11, tzinfo=timezone.utc), ["KB100"])
    leaf = entry("KB300", datetime(2026, 9, 8, tzinfo=timezone.utc), ["KB200"])
    entries = [old, middle, leaf]
    graph = main.patch_supersedence_graph(entries)
    by_key = {x.patch_key: x for x in entries}

    assert graph["kb100"]["obsolete"] is True
    assert graph["kb100"]["replacement_chain_keys"] == ["kb200", "kb300"]
    assert graph["kb100"]["leaf_replacement_keys"] == ["kb300"]
    assert main.choose_preferred_replacement(old, graph["kb100"], by_key).patch_ref == "KB300"


def test_eol_patch_is_review(db):
    db.add(entry(
        "KB-EOL",
        datetime(2025, 1, 14, tzinfo=timezone.utc),
        eol=datetime(2026, 1, 1, tzinfo=timezone.utc),
    ))
    db.commit()
    report = main.patch_catalog_report(db)
    item = report["items"][0]
    assert item["lifecycle"]["eol_state"] == "eol"
    assert item["deployment_readiness"]["status"] == "review"


def test_admin_lifecycle_update_is_persisted(db):
    db.add(entry("KB500"))
    db.commit()

    response = main.update_patch_catalog_lifecycle(
        "KB500",
        PatchCatalogLifecycleUpdate(
            classification="cumulative",
            release_date=datetime(2026, 9, 8, tzinfo=timezone.utc),
            supersedes=["KB400"],
            source="manual",
            reason="Microsoft release metadata reviewed",
        ),
        principal={"actor": "user:admin", "role": "admin"},
        db=db,
    )

    assert response["patch"]["lifecycle"]["classification"] == "cumulative"
    assert response["patch"]["supersedence"]["supersedes"] == ["kb400"]
    assert response["patch"]["lifecycle"]["patch_tuesday"] is True
