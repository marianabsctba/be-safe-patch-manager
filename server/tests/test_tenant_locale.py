import os
import sys
from pathlib import Path

import pytest

TEST_DB = Path(__file__).resolve().parent / "test-tenant-locale.db"
TEST_DB.unlink(missing_ok=True)
SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["ENROLLMENT_TOKEN"] = "P" * 48
os.environ["BREAK_GLASS_ADMIN_TOKEN"] = ""

from app.database import Base, SessionLocal, engine
from app import main
from app.schemas import TenantSettingsUpdate


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


def test_tenant_defaults_to_pt_br(db):
    item = main.tenant_settings(db)
    data = main.serialize_tenant_settings(item)

    assert data["id"] == "default"
    assert data["locale"] == "pt-BR"
    assert {item["code"] for item in data["supported_locales"]} == {"pt-BR", "en", "es"}


@pytest.mark.parametrize("locale", ["pt-BR", "en", "es"])
def test_admin_can_persist_supported_tenant_locale(db, locale):
    result = main.update_tenant_settings(
        TenantSettingsUpdate(locale=locale),
        principal={"actor": "user:admin", "role": "admin"},
        db=db,
    )

    assert result["locale"] == locale
    assert main.tenant_settings(db).locale == locale


def test_tenant_locale_update_is_audited(db):
    main.update_tenant_settings(
        TenantSettingsUpdate(locale="es", name="Be Safe LATAM"),
        principal={"actor": "user:admin", "role": "admin"},
        db=db,
    )

    events = db.query(main.AuditEvent).all()
    assert len(events) == 1
    assert events[0].event_type == "tenant.settings.updated"
    assert events[0].object_type == "tenant"
    assert main.tenant_settings(db).name == "Be Safe LATAM"
